package com.medicare.Auth_Service.Services.TokenService;

import com.medicare.Auth_Service.Model.User;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
@RequiredArgsConstructor
//@Profile("!test")
public class JwtService {

    // RSA key pair for signing and verifying tokens
    private final RSAKey rsaKey;

    // Injected values from application properties
    @Value("${app.issuer}")
    private String issuer;
    @Value("${app.audience:medicare-api}")
    private String audience;
    @Value("${app.access-token-mins:15}")
    private long accessMins;
    @Value("${app.refresh-token-days:7}")
    private long refreshDays;

    /**
     * Issues a signed Access Token for a given user.
     * Contains user identity, role, email, and short expiry time.
     */
    public String issueAccessToken(User user) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)                               // Who created the token
                .audience(audience)                           // Who the token is for
                .subject(user.getUserId())                    // User ID (subject of the token)
                .issueTime(Date.from(now))                    // When the token was issued
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(accessMins)))) // Expiry
                .jwtID(UUID.randomUUID().toString())          // Unique token ID
                .claim("typ", "access")                       // Custom claim: type = access
                .claim("email", user.getEmail())              // Custom claim: email
                .claim("role", user.getRole().name())         // Custom claim: role
                .build();
        return sign(claims); // Sign and return token string
    }

    /**
     * Issues a signed Refresh Token for a given user ID.
     * Longer validity than access token. Contains minimal data.
     */
    public String issueRefreshToken(String userId) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject(userId)                              // user ID only
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofDays(refreshDays)))) // Longer expiry
                .jwtID(UUID.randomUUID().toString())
                .claim("typ", "refresh")                      // Custom claim: type = refresh
                .build();
        return sign(claims);
    }

    /**
     * Parses and validates a token:
     * 1. Verify digital signature with RSA public key.
     * 2. Check issuer matches configured value.
     * 3. Check expiry (must not be expired).
     * Returns claims if valid, otherwise throws SecurityException.
     */
    public JWTClaimsSet parseAndValidate(String jwt) throws Exception {
        SignedJWT signed = SignedJWT.parse(jwt);

        // Verify token signature with public key
        JWSVerifier verifier = new RSASSAVerifier(rsaKey.toPublicJWK());
        if (!signed.verify(verifier))
            throw new SecurityException("Invalid signature");

        // Extract claims
        JWTClaimsSet c = signed.getJWTClaimsSet();

        // Validate issuer
        if (!issuer.equals(c.getIssuer()))
            throw new SecurityException("Invalid issuer");

        // Validate expiry
        if (c.getExpirationTime() == null || c.getExpirationTime().before(new Date()))
            throw new SecurityException("Expired");

        return c; // Return claims if all checks pass
    }

    /**
     * Lightweight check to see if a token is expired.
     * Returns true if expired or has no expiry claim.
     */
    public boolean isExpiredToken(String jwt) throws ParseException, JOSEException {
        SignedJWT signed = SignedJWT.parse(jwt);
        JWTClaimsSet c = signed.getJWTClaimsSet();
        Date exp = c.getExpirationTime();
        if (exp == null) {
            return true; // treat missing exp as expired
        }
        return exp.before(new Date()); // true if expired, false if still valid
    }

    /**
     * Signs claims with RSA private key and returns a compact JWT string.
     */
    private String sign(JWTClaimsSet claims) {
        try {
            // Create RSA signer using private key
            JWSSigner signer = new RSASSASigner(rsaKey.toPrivateKey());

            // Build JWT header (algorithm + key ID + type)
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(rsaKey.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();

            // Combine header + claims and sign
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(signer);

            return jwt.serialize(); // Return token string
        } catch (JOSEException e) {
            throw new IllegalStateException("JWT signing failed", e);
        }
    }
}
