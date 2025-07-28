package com.medicare.Api_Gateway.Filter;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    // List of endpoints that are open (do NOT require authentication)
    public static final List<String> openApiEndpoints = List.of(
            "/auth/signIn",    // User login endpoint
            "/auth/signUp",    // User registration endpoint
            "/auth/validate",  // Token validation (usually for frontend)
            "/eureka"          // Eureka service registry (should remain open)
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
