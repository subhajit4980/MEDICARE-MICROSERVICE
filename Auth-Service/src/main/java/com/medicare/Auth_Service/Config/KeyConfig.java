package com.medicare.Auth_Service.Config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
@RequiredArgsConstructor
public class KeyConfig {

    // Custom properties holder (contains Base64/PEM encoded RSA keys)
    private final RsaKeyProperties rsaProps;

    // Key ID used in JWK (helpful when rotating keys in future)
    @Value("${app.jwks.key-id:auth-key-2025}")
    private String keyId;

    // ---------------- RSA Key Beans ----------------

    @Bean
    public RSAPublicKey rsaPublicKey() throws Exception {
        // Load and convert configured public key into RSAPublicKey
        return loadPublicKey(rsaProps.publicKeyB64());
    }

    @Bean
    public RSAPrivateKey rsaPrivateKey() throws Exception {
        // Load and convert configured private key into RSAPrivateKey
        return loadPrivateKey(rsaProps.privateKeyB64());
    }

    @Bean
    public RSAKey rsaJwk(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        // Create a JWK (JSON Web Key) representation of the RSA keypair
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId) // key identifier for JWKS endpoint
                .build();
    }

    @Bean
    public JWKSet jwkSet(RSAKey rsaJwk) {
        // JWKS (JSON Web Key Set) exposed via an endpoint (/oauth2/jwks)
        return new JWKSet(rsaJwk.toPublicJWK());
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaJwk) {
        // Provides JWK source for JWT signing/verification
        return new ImmutableJWKSet<>(new JWKSet(rsaJwk));
    }

    // ---------------- JWT Encoder/Decoder ----------------

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        // Encoder used to generate JWT tokens (sign with private key)
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAPublicKey publicKey) {
        // Decoder used to verify and parse JWT tokens (verify with public key)
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    // ---------------- Helper Methods ----------------

    private RSAPublicKey loadPublicKey(String maybePemOrB64) throws Exception {
        // Convert string (PEM or Base64) into RSAPublicKey
        byte[] der = extractDerBytes(maybePemOrB64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    private RSAPrivateKey loadPrivateKey(String maybePemOrB64) throws Exception {
        // Convert string (PEM or Base64) into RSAPrivateKey
        byte[] der = extractDerBytes(maybePemOrB64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(spec);
    }

    /**
     * Handles different formats of RSA keys:
     * - PEM text (with -----BEGIN/END----- headers)
     * - Base64 of DER bytes
     * - Base64 of entire PEM file (double encoded)
     */
    private byte[] extractDerBytes(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Key property is empty");
        }
        String trimmed = input.trim();

        // Case A: PEM format → strip headers and decode Base64 body
        if (trimmed.contains("-----BEGIN")) {
            String body = stripPemHeaders(trimmed);
            return Base64.getDecoder().decode(body);
        }

        // Case B: Plain Base64 → decode directly
        byte[] decoded = Base64.getDecoder().decode(trimmed);

        // Extra: Handle case where decoded result is still PEM text
        String asString = new String(decoded, StandardCharsets.UTF_8);
        if (asString.contains("-----BEGIN")) {
            String body = stripPemHeaders(asString);
            return Base64.getDecoder().decode(body);
        }

        // Otherwise → already raw DER
        return decoded;
    }

    // Removes PEM headers/footers and whitespace
    private String stripPemHeaders(String pem) {
        return pem
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");
    }
}
