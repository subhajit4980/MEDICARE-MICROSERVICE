package com.medicare.Notification_Service.Controller;

import com.medicare.Notification_Service.Service.EmailService.EmailService;
import com.medicare.Notification_Service.Service.SmsService.SmsService;
import freemarker.template.Configuration;
import freemarker.template.Template;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
public class NotificationController {

    private final SmsService notificationService;
    private final EmailService emailService;
    private final Configuration config;


    @PostMapping("/send-sms")
    public String sendSms(
            @RequestParam String phoneNumber,
            @RequestParam String message
    ) {
        System.out.println(phoneNumber);
        return notificationService.sendSms(phoneNumber, message);
    }

    @PostMapping("/send-Welcome-mail")
    public boolean sendWelcomeMail(@RequestParam String fullName,
                                             @RequestParam String mailId)
            throws IOException, MessagingException {
        Map<String, Object> model = new HashMap<>();
        model.put("Name", fullName);
        model.put("medicareWebsiteUrl", "https://subhajit4980.github.io/Subhajit/");
        Template t = config.getTemplate("email-template.ftl");
        final String WelcomeSubject = "Welcome to Medicare - Your Journey to Health Begins Here!";
        emailService.sendEmail(mailId, WelcomeSubject, t, model);
        return true;
    }

    @PostMapping("/send-Otp")
    public ResponseEntity<?> sendOtp(@RequestParam String fullName,
                                     @RequestParam String mailId,
                                     @RequestParam String otp,
                                     @RequestParam String type)
            throws IOException, MessagingException {
        Map<String, Object> model = new HashMap<>();
        model.put("Name", fullName);
        model.put("otp", otp);
        Template t = null;
        if (type.equals("password"))
            t = config.getTemplate("Password-Reset-Otp-template.ftl");
        else if (type.equals("verify")) {
            t = config.getTemplate("Verify-Account-Otp.ftl");
        }
        final String WelcomeSubject = "Password Reset Request";
        emailService.sendEmail(mailId, WelcomeSubject, t, model);
        return ResponseEntity.ok("Mail send");
    }
}
