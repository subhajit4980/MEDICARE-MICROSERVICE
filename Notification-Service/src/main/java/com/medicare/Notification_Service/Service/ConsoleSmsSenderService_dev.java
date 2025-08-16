package com.medicare.Notification_Service.Service;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile("dev")
public class ConsoleSmsSenderService_dev implements SmsSender {
    @Override
    public String sendSms(String phoneNumber, String message) {
        System.out.println("DEV MODE - sms for " + phoneNumber + " is: " + message);
        return  "SMS send";
    }
}
