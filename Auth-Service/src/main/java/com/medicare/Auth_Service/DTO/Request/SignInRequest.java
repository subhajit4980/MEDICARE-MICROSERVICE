package com.medicare.Auth_Service.DTO.Request;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class SignInRequest {
    @NotBlank
    private String email;
    @NotBlank
    private String password;

}