package com.medicare.Notification_Service.Service;

public interface SmsSender {
     String sendSms(String phoneNumber, String message);
}
