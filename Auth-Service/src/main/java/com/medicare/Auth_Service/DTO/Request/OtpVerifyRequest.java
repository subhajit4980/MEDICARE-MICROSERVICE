package com.medicare.Auth_Service.DTO.Request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class OtpVerifyRequest {
    @NotBlank
    private String phone;
    @NotBlank
    private String otp;
    @NotBlank
    private  String sessionId;
}
