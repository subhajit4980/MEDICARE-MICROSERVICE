package com.medicare.Api_Gateway.Filter;

import com.medicare.Api_Gateway.Exception.UserException;
import com.medicare.Api_Gateway.Route.RouteValidator;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
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
import java.util.Date;
import java.util.List;

import static com.medicare.Api_Gateway.Route.RouteValidator.roleProtectedEndpoints;

/**
 * Gateway Filter responsible for:
 * <p>
 * 1. Checking if the request requires authentication
 * 2. Validating JWT using Auth-Service JWKS public keys
 * 3. Verifying signature and expiration
 * 4. Enforcing role-based access control
 * 5. Injecting user information into request headers
 */
@Component
public class JwtAuthGatewayFilterFactory
        extends AbstractGatewayFilterFactory<JwtAuthGatewayFilterFactory.Config> {

    private static final Logger log =
            LoggerFactory.getLogger(JwtAuthGatewayFilterFactory.class);

    private final RouteValidator validator;
    private final LoadBalancerClient loadBalancerClient;

    /**
     * Remote JWK set containing Auth-Service public keys.
     * Used to verify JWT signatures.
     */
    private volatile RemoteJWKSet<SecurityContext> jwkSet;

    @Autowired
    public JwtAuthGatewayFilterFactory(RouteValidator validator,
                                       LoadBalancerClient loadBalancerClient) {
        super(Config.class);
        this.validator = validator;
        this.loadBalancerClient = loadBalancerClient;
        log.info("JwtAuthGatewayFilter initialized. Waiting for Auth-Service JWKS...");
    }

    /**
     * Periodically tries to resolve Auth-Service
     * and fetch its JWKS endpoint containing public keys.
     * <p>
     * This allows JWT verification without calling Auth-Service
     * for every request.
     */
    @Scheduled(fixedDelay = 10000)
    public void refreshAuthServiceJwk() {

        if (jwkSet != null) {
            log.debug("JWKS already initialized. Skipping refresh.");
            return;
        }
        try {
            ServiceInstance instance =
                    loadBalancerClient.choose("auth-service");
            if (instance == null) {
                log.warn("Auth-Service instance not available yet. Retrying...");
                return;
            }

            String jwksUrl = String.format(
                    "http://%s:%d/auth/.well-known/jwks.json",
                    instance.getHost(),
                    instance.getPort()
            );

            this.jwkSet = new RemoteJWKSet<>(
                    new URL(jwksUrl),
                    new com.nimbusds.jose.util.DefaultResourceRetriever(
                            5000, 5000, 3600 * 1000
                    )
            );
            log.info("Connected to Auth-Service JWKS endpoint: {}", jwksUrl);
        } catch (Exception e) {
            log.error("Failed to initialize JWKS from Auth-Service", e);
        }
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {
            String path = exchange.getRequest().getURI().getPath();
            /**
             * Skip authentication if endpoint is public
             */
            if (!validator.isSecured.test(exchange.getRequest())) {
                log.debug("OPEN endpoint → {}. JWT validation skipped.", path);
                return chain.filter(exchange);
            }

            log.info("SECURED endpoint → {}. Starting JWT validation.", path);

            /**
             * Ensure JWKS is available before verifying tokens
             */
            if (jwkSet == null) {
                log.error("JWKS not initialized. Auth-Service may be unavailable.");
                refreshAuthServiceJwk();
            }
            /**
             * Extract Authorization header
             */
            String authHeader = exchange.getRequest()
                    .getHeaders()
                    .getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Missing Authorization header for path={}", path);
                return Mono.error(new UserException(
                        HttpStatus.UNAUTHORIZED,
                        "Missing Authorization header"
                ));
            }
            try {
                /**
                 * Extract JWT token
                 */
                String token = authHeader.substring(7);
                SignedJWT signedJWT = SignedJWT.parse(token);
                log.debug("JWT parsed successfully. kid={}",
                        signedJWT.getHeader().getKeyID());

                /**
                 * Select matching JWK using token kid
                 */
                JWKSelector selector = new JWKSelector(
                        new JWKMatcher.Builder()
                                .keyID(signedJWT.getHeader().getKeyID())
                                .build()
                );

                List<JWK> jwks = jwkSet.get(selector, null);

                if (jwks.isEmpty()) {
                    log.error("No matching JWK found for kid={} path={}",
                            signedJWT.getHeader().getKeyID(), path);
                    return Mono.error(new UserException(
                            HttpStatus.UNAUTHORIZED,
                            "No matching JWK for kid=" +
                                    signedJWT.getHeader().getKeyID()
                    ));
                }

                /**
                 * Verify JWT signature using RSA public key
                 */
                RSAKey rsaKey = (RSAKey) jwks.get(0);
                JWSVerifier verifier =
                        new RSASSAVerifier(rsaKey.toRSAPublicKey());
                if (!signedJWT.verify(verifier)) {
                    log.error("Invalid JWT signature path={}", path);
                    return Mono.error(new UserException(
                            HttpStatus.UNAUTHORIZED,
                            "Invalid JWT signature"
                    ));
                }
                log.debug("JWT signature verified successfully");

                /**
                 * Extract claims
                 */
                var claims = signedJWT.getJWTClaimsSet();
                log.debug("JWT claims → userId={} role={}",
                        claims.getSubject(),
                        claims.getClaim("role"));
                /**
                 * Validate expiration
                 */
                if (claims.getExpirationTime().before(new Date())) {
                    log.warn("Expired token userId={} path={}",
                            claims.getSubject(), path);
                    return Mono.error(new UserException(
                            HttpStatus.UNAUTHORIZED,
                            "Token expired"
                    ));
                }

                /**
                 * Role based access control
                 */
                Object roleClaim = claims.getClaim("role");
                String role = roleClaim != null
                        ? roleClaim.toString()
                        : "";

                List<String> allowedRoles =
                        roleProtectedEndpoints.entrySet()
                                .stream()
                                .filter(e -> path.contains(e.getKey()))
                                .flatMap(e -> e.getValue().stream())
                                .toList();
                log.info("list if role allowed for the endpoint = {}",allowedRoles.toString());
                if (!allowedRoles.isEmpty() && !allowedRoles.contains(role)) {

                    log.warn("Access denied userId={} role={} path={}",
                            claims.getSubject(), role, path);

                    return Mono.error(new UserException(
                            HttpStatus.FORBIDDEN,
                            "Access denied for role " + role
                    ));
                }

                /**
                 * Inject user details into request headers
                 * so downstream services can access them
                 */
                var mutatedExchange = exchange.mutate()
                        .request(r -> r.headers(headers -> {
                            headers.add("X-User-Id", claims.getSubject());
                            headers.add("X-User-Email",
                                    (String) claims.getClaim("email"));
                            headers.add("X-User-Role", role);
                        }))
                        .build();
                log.info("JWT validated successfully path={} userId={}",
                        path, claims.getSubject());
                return chain.filter(mutatedExchange);

            } catch (Exception e) {
                log.error("JWT verification failed path={}", path, e);
                return Mono.error(new UserException(
                        HttpStatus.UNAUTHORIZED,
                        "JWT verification failed: " + e.getMessage()
                ));
            }
        };
    }

    /**
     * Configuration class required by
     * AbstractGatewayFilterFactory
     */
    public static class Config {
    }
}