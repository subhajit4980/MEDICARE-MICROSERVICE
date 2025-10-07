package com.medicare.Notification_Service.Service.SmsService;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Profile("prod")
public class SmsService_prod {
    private final SmsSender smsSender;

    public String sendSms(String phoneNumber, String message) {
        System.out.println("phone:" + phoneNumber + " , message: " + message);
        return smsSender.sendSms(phoneNumber, message);
    }
}
