package com.medicare.Auth_Service.DTO.Response;

import com.medicare.Auth_Service.Model.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthResult {
    private User user;
    private String accessToken;
}
