package com.medicare.Auth_Service.DTO.Request;

import com.medicare.Auth_Service.Model.Enum.Role;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class ValidateRequest {
    @NotBlank
    private String email;
    @NotBlank
    private String password;
    @NotBlank
    private Role role;
    @NotBlank
    private String token;

}