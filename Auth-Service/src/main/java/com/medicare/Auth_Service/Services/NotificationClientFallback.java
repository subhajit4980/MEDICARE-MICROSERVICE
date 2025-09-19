//package com.medicare.Auth_Service.Services;
//
//import org.springframework.http.ResponseEntity;
//import org.springframework.stereotype.Component;
//
//@Component
//public class NotificationClientFallback implements NotificationClient {
//
//    @Override
//    public String sendSms(String phoneNumber, String message) {
//        // For testing, throw exception instead of returning dummy
//        throw new RuntimeException("Notification service unreachable");
//    }
//
//    @Override
//    public ResponseEntity<?> sendWelcomeMail(String fullName, String mailId) {
//        return null;
//    }
//
//    @Override
//    public ResponseEntity<?> sendOtp(String fullName, String mailId, String otp, String type) {
//        return null;
//    }
//}
