// GlobalExceptionHandler.java
package com.medicare.Auth_Service.Exception;

import com.medicare.Auth_Service.DTO.Response.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import jakarta.validation.ConstraintViolationException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Production-grade global exception handler.
 * - Keeps domain-specific handlers (UserException)
 * - Handles validation errors (MethodArgumentNotValidException, ConstraintViolationException)
 * - Sanitizes generic exceptions (no stacktrace leaked to clients)
 * - Includes traceId/correlationId and request path for observability
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final String TRACE_HEADER = "X-Correlation-ID";

    @ExceptionHandler(UserException.class)
    public ResponseEntity<ErrorResponse> handleUserException(UserException ex, HttpServletRequest request) {
        ErrorResponse body = ErrorResponse.builder()
                .timestamp(Instant.now().toString())
                .status(ex.getStatus())
                .error(ex.getStatusCode().getReasonPhrase().toLowerCase().replace(' ', '_'))
                .message(ex.getMessage())
                .path(request.getRequestURI())
                .traceId(getTraceId(request))
                .details(Map.of("errorCode", ex.getErrorCode()))
                .build();

        return ResponseEntity.status(ex.getStatusCode()).body(body);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        List<String> errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(f -> f.getField() + ": " + (f.getDefaultMessage() == null ? f.toString() : f.getDefaultMessage()))
                .collect(Collectors.toList());

        Map<String, Object> details = new HashMap<>();
        details.put("fieldErrors", errors);

        ErrorResponse body = ErrorResponse.builder()
                .timestamp(Instant.now().toString())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("validation_error")
                .message("Validation failed for request")
                .path(request.getRequestURI())
                .traceId(getTraceId(request))
                .details(details)
                .build();

        return ResponseEntity.badRequest().body(body);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest request) {
        List<String> violations = ex.getConstraintViolations()
                .stream()
                .map(cv -> cv.getPropertyPath() + ": " + cv.getMessage())
                .collect(Collectors.toList());

        Map<String, Object> details = new HashMap<>();
        details.put("violations", violations);

        ErrorResponse body = ErrorResponse.builder()
                .timestamp(Instant.now().toString())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("constraint_violation")
                .message("Request parameters validation failed")
                .path(request.getRequestURI())
                .traceId(getTraceId(request))
                .details(details)
                .build();

        return ResponseEntity.badRequest().body(body);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleBadRequestBody(HttpMessageNotReadableException ex, HttpServletRequest request) {
        ErrorResponse body = ErrorResponse.builder()
                .timestamp(Instant.now().toString())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("malformed_request")
                .message("Malformed request body or invalid JSON")
                .path(request.getRequestURI())
                .traceId(getTraceId(request))
                .details(Map.of("exception", ex.getMostSpecificCause() != null ? ex.getMostSpecificCause().getMessage() : ex.getMessage()))
                .build();

        return ResponseEntity.badRequest().body(body);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        ErrorResponse body = ErrorResponse.builder()
                .timestamp(Instant.now().toString())
                .status(HttpStatus.FORBIDDEN.value())
                .error("access_denied")
                .message("You don't have permission to access this resource")
                .path(request.getRequestURI())
                .traceId(getTraceId(request))
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(Exception ex, HttpServletRequest request) {
        ex.printStackTrace(); // replace with logger.error(...) in production

        ErrorResponse body = ErrorResponse.builder()
                .timestamp(Instant.now().toString())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .error("internal_error")
                .message("An unexpected error occurred. Please contact support with traceId.")
                .path(request.getRequestURI())
                .traceId(getTraceId(request))
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }

    private String getTraceId(HttpServletRequest request) {
        String h = request.getHeader(TRACE_HEADER);
        return (h == null || h.isBlank()) ? java.util.UUID.randomUUID().toString() : h;
    }
}
