// UserException.java
package com.medicare.Auth_Service.Exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Domain-level exception with an HttpStatus and optional details.
 */
@Getter
public class UserException extends RuntimeException {
    private final int status;
    private final HttpStatus statusCode;
    private final String errorCode;

    public UserException(HttpStatus statusCode, String errorMessage) {
        super(errorMessage);
        this.statusCode = statusCode;
        this.status = statusCode.value();
        this.errorCode = null;
    }

    public UserException(HttpStatus statusCode, String errorMessage, String errorCode) {
        super(errorMessage);
        this.statusCode = statusCode;
        this.status = statusCode.value();
        this.errorCode = errorCode;
    }
}
