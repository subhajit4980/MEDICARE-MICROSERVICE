package com.medicare.Api_Gateway.Filter;

import com.medicare.Api_Gateway.Exception.UserException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URL;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

@Component
public class JwtAuthGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtAuthGatewayFilterFactory.Config> {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthGatewayFilterFactory.class);

    private final RemoteJWKSet<SecurityContext> jwkSet;
    private final RouteValidator validator;

    public JwtAuthGatewayFilterFactory(RouteValidator validator) throws Exception {
        super(Config.class);
        this.validator = validator;
        log.info(">>> JwtAuthFilter initialized and registered");
        // Auth-Service JWKS endpoint (through Gateway)
        this.jwkSet = new RemoteJWKSet<>(
                new URL("http://localhost:8765/auth-service/auth/.well-known/jwks.json"),
                new com.nimbusds.jose.util.DefaultResourceRetriever(5000, 5000, 3600 * 1000)
        );
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String path = exchange.getRequest().getURI().getPath();
            // Skip auth if endpoint is open
            if (!validator.isSecured.test(exchange.getRequest())) {
                log.info("[OPEN] {} → skipping JwtAuthFilter", path);
                return chain.filter(exchange);
            }
            log.info("[SECURED] {} → validating JWT", path);

            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.error("[ERROR] {} → Missing Authorization header", path);
                return Mono.error(new UserException(HttpStatus.UNAUTHORIZED, "Missing Authorization header"));
            }

            try {
                String token = authHeader.substring(7);
                SignedJWT signedJWT = SignedJWT.parse(token);

                // Match JWK by kid
                JWKSelector selector = new JWKSelector(
                        new JWKMatcher.Builder().keyID(signedJWT.getHeader().getKeyID()).build()
                );
                List<JWK> jwks = jwkSet.get(selector, null);
                if (jwks.isEmpty()) {
                    log.error("[ERROR] {} → No matching JWK for kid={}", path, signedJWT.getHeader().getKeyID());
                    return Mono.error(new UserException(HttpStatus.UNAUTHORIZED,
                            "No matching JWK for kid=" + signedJWT.getHeader().getKeyID()));
                }
                log.info("Token kid = {}", signedJWT.getHeader().getKeyID());
                // Verify signature
                RSAKey rsaKey = (RSAKey) jwks.get(0);
                log.info("Using kid={} alg={} to verify token", rsaKey.getKeyID(), rsaKey.getAlgorithm());
                JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
                if (!signedJWT.verify(verifier)) {
                    log.info("Token Header: {}", signedJWT.getHeader().toJSONObject());
                    log.info("Token Payload: {}", signedJWT.getPayload().toString());
                    log.info("Available JWKS: {}", jwks);
                    log.error("[ERROR] {} → Invalid JWT signature", path);
                    return Mono.error(new UserException(HttpStatus.UNAUTHORIZED, "Invalid JWT signature"));
                }

                // Check expiration
                var claims = signedJWT.getJWTClaimsSet();
                if (claims.getExpirationTime().before(new Date())) {
                    log.error("[ERROR] {} → Token expired", path);
                    return Mono.error(new UserException(HttpStatus.UNAUTHORIZED, "Token expired"));
                }

                // Add claims → request headers
                var mutatedExchange = exchange.mutate()
                        .request(r -> r.headers(headers -> {
                            headers.add("X-User-Id", claims.getSubject());
                            headers.add("X-User-Email", (String) claims.getClaim("email"));
                            try {
                                headers.add("X-User-Role",
                                        String.join(",", claims.getStringListClaim("role")));
                            } catch (ParseException e) {
                                headers.add("X-User-Role", "");
                            }
                        }))
                        .build();

                log.info("[OK] {} → JWT validated, headers injected", path);
                return chain.filter(mutatedExchange);

            } catch (Exception e) {
                log.error("[ERROR] {} → JWT verification failed: {}", path, e.getMessage());
                return Mono.error(new UserException(HttpStatus.UNAUTHORIZED,
                        "JWT verification failed: " + e.getMessage()));
            }
        };
    }

    public static class Config {
    }
}
