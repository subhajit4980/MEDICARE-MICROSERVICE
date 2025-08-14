package com.medicare.Auth_Service.Exception;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

@Getter
@Setter
public class UserException extends RuntimeException {
    private int status;
    private HttpStatus statusCode;
    public UserException(HttpStatus status,String message) {
        super(message);
        this.status=status.value();
        this.statusCode=status;
    }
}
