package com.medicare.Api_Gateway.Route;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    // List of endpoints that are open (do NOT require authentication)
    public static final List<String> openApiEndpoints = List.of(
            "/auth/signIn",    // User login endpoint
            "/auth/signUp",    // User registration endpoint
            "/auth/send-otp",
            "/auth/forgot-password",
            "/auth/verify-otp",
            "/auth/verify-User",
            "/auth/update-password",
            "/auth/refreshToken",
            "/auth/validate",
            "/auth/google-login",
            "/auth/.well-known/jwks.json",
            "/api/eureka" ,        // Eureka service registry (should remain open)
            "/v2/api-docs",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui/**",
            "/webjars/**",
            "/swagger-ui.html"
    );
    public static final Map<String, List<String>> roleProtectedEndpoints = Map.of(
            "/admin", List.of("ADMIN"),
            "/user/profile", List.of("USER", "ADMIN", "MANAGER")
    );

    /**
     * Predicate to determine if a given HTTP request targets a secured endpoint.
     * It returns true if the request is NOT in the openApiEndpoints list,
     * meaning it must be secured (i.e., requires authentication).
     */
    public Predicate<ServerHttpRequest> isSecured =
            request -> openApiEndpoints
                    .stream()
                    .noneMatch(uri -> request.getURI().getPath().contains(uri));
}
