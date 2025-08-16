package com.medicare.Notification_Service.Service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SmsService {
    private  final SmsSender smsSender;
    public String sendSms(String phoneNumber, String message)
    {
        return smsSender.sendSms(phoneNumber,message);
    }
}
