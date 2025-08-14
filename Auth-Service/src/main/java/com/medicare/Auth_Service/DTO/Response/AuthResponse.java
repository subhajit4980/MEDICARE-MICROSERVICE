package com.medicare.Auth_Service.DTO.Response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.medicare.Auth_Service.Model.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("User_Details")
    private User user;
}
