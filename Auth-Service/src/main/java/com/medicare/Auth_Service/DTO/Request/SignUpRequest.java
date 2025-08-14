package com.medicare.Auth_Service.DTO.Request;
import com.medicare.Auth_Service.Model.Enum.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;


@Data
public class SignUpRequest {
    @NotBlank
    private String firstName;
    @NotBlank
    private String lastName;
    @NotBlank
    @Size(max = 50)
    @Email
    private String email;
    private Role role;
    @NotBlank
    @Size(min = 6, max = 40)
    private String password;
}
