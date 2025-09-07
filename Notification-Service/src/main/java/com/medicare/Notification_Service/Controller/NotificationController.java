package com.medicare.Notification_Service.Controller;

import com.medicare.Notification_Service.Service.SmsService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
public class NotificationController {

    private final SmsService notificationService;

    @PostMapping("/send-sms")
    public String sendSms(
            @RequestParam String phoneNumber,
            @RequestParam String message
    ) {
        System.out.println(phoneNumber);
        return notificationService.sendSms(phoneNumber, message);
    }
}
