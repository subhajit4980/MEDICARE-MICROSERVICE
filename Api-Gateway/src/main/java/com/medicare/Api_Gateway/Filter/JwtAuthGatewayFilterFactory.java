package com.medicare.Api_Gateway.Filter;

import com.medicare.Api_Gateway.Exception.UserException;
import com.medicare.Api_Gateway.Route.RouteValidator;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URL;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

@Component
public class JwtAuthGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtAuthGatewayFilterFactory.Config> {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthGatewayFilterFactory.class);

    private final RouteValidator validator;
    private final LoadBalancerClient loadBalancerClient;
    private volatile RemoteJWKSet<SecurityContext> jwkSet;

    @Autowired
    public JwtAuthGatewayFilterFactory(RouteValidator validator, LoadBalancerClient loadBalancerClient) {
        super(Config.class);
        this.validator = validator;
        this.loadBalancerClient = loadBalancerClient;
        log.info(">>> JwtAuthFilter initialized. Waiting for Auth-Service JWKS...");
    }

    /**
     * Periodically try to resolve auth-service and load JWKS
     */
    @Scheduled(fixedDelay = 10000) // every 10s
    public void refreshAuthServiceJwk() {
        if (jwkSet != null) return; // already initialized

        try {
            ServiceInstance instance = loadBalancerClient.choose("auth-service");
            if (instance != null) {
                String jwksUrl = String.format("http://%s:%d/auth/.well-known/jwks.json",
                        instance.getHost(), instance.getPort());

                this.jwkSet = new RemoteJWKSet<>(
                        new URL(jwksUrl),
                        new com.nimbusds.jose.util.DefaultResourceRetriever(5000, 5000, 3600 * 1000)
                );
                log.info("✅ Connected to Auth-Service, JWKS endpoint = {}", jwksUrl);
            } else {
                log.warn("Auth-Service not available yet, will retry...");
            }
        } catch (Exception e) {
            log.error("Failed to initialize JWKS from Auth-Service: {}", e.getMessage());
        }
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

            // If jwkSet not ready, block request with 503
            if (jwkSet == null) {
                log.error("[ERROR] {} → Auth-Service not connected to api gateway ❌", path);
                refreshAuthServiceJwk();
            }

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
