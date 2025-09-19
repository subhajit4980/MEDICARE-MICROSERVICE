package com.medicare.Notification_Service.Service.SmsService;

public interface SmsSender {
    String sendSms(String phoneNumber, String message);
}
