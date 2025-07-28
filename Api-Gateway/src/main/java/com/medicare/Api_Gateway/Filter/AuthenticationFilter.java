package com.medicare.Api_Gateway.Filter;

import com.medicare.Api_Gateway.Exception.UserException;
import com.medicare.Api_Gateway.Utils.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

    @Autowired
    private JwtUtils jwtUtil;

    @Autowired
    private RouteValidator validator; // Checks if the route is secured

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            // Check if the requested route is secured (authentication required)
            if (validator.isSecured.test(exchange.getRequest())) {

                // Extract Authorization header from the request
                List<String> authHeaders = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);

                if (authHeaders == null || authHeaders.isEmpty()) {
                    logger.warn("Missing Authorization header");
                    throw new UserException(HttpStatus.UNAUTHORIZED, "Missing Authorization header");
                }

                // Extract Bearer token
                String authHeader = authHeaders.get(0);
                String token = null;

                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    token = authHeader.substring(7); // Remove "Bearer " prefix
                } else {
                    logger.warn("Authorization header does not start with Bearer");
                    throw new UserException(HttpStatus.UNAUTHORIZED, "Invalid Authorization header format");
                }

                // Validate JWT token
                try {
                    jwtUtil.validateToken(token);
                    logger.info("JWT validated successfully");
                } catch (Exception e) {
                    logger.error("JWT validation failed: {}", e.getMessage());
                    throw new UserException(HttpStatus.UNAUTHORIZED, "Unauthorized access to application");
                }

                // Optional: You can also extract claims and pass them downstream
                // Example:
                // Claims claims = jwtUtil.getClaims(token);
                // exchange.getRequest().mutate().header("X-User-Id", claims.getSubject()).build();
            }

            // Proceed with the request if everything is valid
            return chain.filter(exchange);
        };
    }

    // Empty config class required by Spring Cloud Gateway filter factory pattern
    public static class Config { }
}
