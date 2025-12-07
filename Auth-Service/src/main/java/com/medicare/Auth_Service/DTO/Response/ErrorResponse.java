package com.medicare.Auth_Service.DTO.Response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;

/**
 * Standardized error response used across services.
 * Produces a JSON structure similar to RFC7807 (problem+json) with additional fields.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ErrorResponse {
    private String timestamp = Instant.now().toString();
    private int status;
    private String error;
    private String message;
    private String path;
    private String traceId;
    private Map<String, Object> details;
}
