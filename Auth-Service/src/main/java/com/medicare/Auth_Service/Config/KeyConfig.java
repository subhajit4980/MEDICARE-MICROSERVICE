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
//@Profile("!test")
@RequiredArgsConstructor
public class KeyConfig {

    private final RsaKeyProperties rsaProps;

    @Value("${app.jwks.key-id:auth-key-2025}")
    private String keyId;

    @Bean
    public RSAPublicKey rsaPublicKey() throws Exception {
        return loadPublicKey(rsaProps.publicKeyB64());
    }

    @Bean
    public RSAPrivateKey rsaPrivateKey() throws Exception {
        return loadPrivateKey(rsaProps.privateKeyB64());
    }

    @Bean
    public RSAKey rsaJwk(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();
    }

    @Bean
    public JWKSet jwkSet(RSAKey rsaJwk) {
        return new JWKSet(rsaJwk.toPublicJWK());
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaJwk) {
        return new ImmutableJWKSet<>(new JWKSet(rsaJwk));
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAPublicKey publicKey) {
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    // ---------- helper methods ----------
    private RSAPublicKey loadPublicKey(String maybePemOrB64) throws Exception {
        byte[] der = extractDerBytes(maybePemOrB64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    private RSAPrivateKey loadPrivateKey(String maybePemOrB64) throws Exception {
        byte[] der = extractDerBytes(maybePemOrB64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(spec);
    }

    /**
     * Accepts:
     * - raw PEM text (contains -----BEGIN ...-----)
     * - base64 of DER bytes (single-line)
     * - base64 of entire PEM file (decodes to PEM text)
     */
    private byte[] extractDerBytes(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Key property is empty");
        }
        String trimmed = input.trim();

        // A) If it contains PEM headers -> strip and decode body
        if (trimmed.contains("-----BEGIN")) {
            String body = stripPemHeaders(trimmed);
            return Base64.getDecoder().decode(body);
        }

        // B) Else attempt to decode base64
        byte[] decoded = Base64.getDecoder().decode(trimmed);

        // If decoded bytes look like PEM text (someone base64'd the entire PEM), handle that
        String asString = new String(decoded, StandardCharsets.UTF_8);
        if (asString.contains("-----BEGIN")) {
            String body = stripPemHeaders(asString);
            return Base64.getDecoder().decode(body);
        }

        // Otherwise, decoded bytes are DER bytes already
        return decoded;
    }

    private String stripPemHeaders(String pem) {
        return pem
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");
    }
}
