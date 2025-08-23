package com.medicare.Api_Gateway.Filter;

import com.medicare.Api_Gateway.Exception.UserException;
import com.medicare.Api_Gateway.Utils.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);
    @Autowired
    public JwtUtils jwtUtil;
    @Autowired
    private RouteValidator validator; // Checks if the route is secured
    @Autowired
    private Oauth2Validator oauth2Validator;
    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            // ✅ Only secure routes require authentication
            if (validator.isSecured.test(exchange.getRequest())) {

                // Extract Authorization header
                List<String> authHeaders = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
                if (authHeaders == null || authHeaders.isEmpty()) {
                    logger.warn("Missing Authorization header");
                    throw new UserException(HttpStatus.UNAUTHORIZED, "Missing Authorization header");
                }

                String authHeader = authHeaders.get(0);
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    logger.warn("Authorization header does not start with Bearer");
                    throw new UserException(HttpStatus.UNAUTHORIZED, "Invalid Authorization header format");
                }

                // ✅ Extract token
                String token = authHeader.substring(7);

                // Track which type of token it is
                String tokenType = "";

                try {
                    // ✅ Case 1: Internal JWT
                    if (jwtUtil.isJwt(token)) {
                        jwtUtil.validateToken(token);
                        logger.info("JWT validated successfully");
                        tokenType = "JWT";
                    }
                    // ✅ Case 2: Google OAuth2 Token
                    else if (Oauth2Validator.validateGoogleToken(token)) {
                        logger.info("Google OAuth2 token validated successfully");
                        tokenType = "GOOGLE";
                    }
                    // ✅ Invalid token
                    else {
                        logger.warn("Token is not a valid JWT or Google token");
                        throw new UserException(HttpStatus.UNAUTHORIZED, "Invalid or expired token");
                    }

                } catch (Exception e) {
                    logger.error("Token validation failed: {}", e.getMessage());
                    throw new UserException(HttpStatus.UNAUTHORIZED, "Unauthorized access to application");
                }

                // (Optional) Pass token type downstream
                exchange.getRequest().mutate()
                        .header("X-Token-Type", tokenType)
                        .build();
            }

            return chain.filter(exchange);
        };
    }

    // Empty config class required by Spring Cloud Gateway filter factory pattern
    public static class Config { }
}
