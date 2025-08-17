package com.medicare.Auth_Service.Services;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "notification-service" ,fallback = NotificationClientFallback.class) // matches service name in Eureka
public interface NotificationClient {
    @PostMapping("/api/notifications/send-sms")
    String sendSms(@RequestParam("phoneNumber") String phone,
                   @RequestParam("message") String message);
}
