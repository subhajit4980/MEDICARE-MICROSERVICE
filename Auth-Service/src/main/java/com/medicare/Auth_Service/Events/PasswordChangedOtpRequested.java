package com.medicare.Auth_Service.Events;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor

public class PasswordChangedOtpRequested {
    String otp;
    String email;
}
