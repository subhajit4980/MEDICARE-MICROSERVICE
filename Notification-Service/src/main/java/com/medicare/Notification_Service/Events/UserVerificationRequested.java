package com.medicare.Notification_Service.Events;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserVerificationRequested {
    private String otp;
    private String fullName;
    private String email;
}

