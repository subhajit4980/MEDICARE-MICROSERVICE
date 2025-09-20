package com.medicare.Notification_Service.Service.EmailService;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medicare.Notification_Service.Events.UserRegisteredEvent;
import com.medicare.Notification_Service.Events.UserVerificationRequested;
import freemarker.template.Configuration;
import freemarker.template.Template;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class NotificationListener {

    private final ObjectMapper objectMapper;
    private final EmailService emailService;
    private final Configuration config;

    @KafkaListener(topics = "user-registered-topic", groupId = "notification-group")
    public void onUserRegistered(String payload, @Header(KafkaHeaders.RECEIVED_KEY) String key) throws Exception {
        UserRegisteredEvent event = objectMapper.readValue(payload, UserRegisteredEvent.class);
        try {
            Map<String, Object> model = new HashMap<>();
            model.put("Name", event.getFullName());
            model.put("medicareWebsiteUrl", "https://subhajit4980.github.io/Subhajit/");
            Template t = config.getTemplate("email-template.ftl");
            final String WelcomeSubject = "Welcome to Medicare - Your Journey to Health Begins Here!";
            emailService.sendEmail(event.getEmail(), WelcomeSubject, t, model);

        } catch (Exception ex) {
            // rethrow to let DefaultErrorHandler handle retries and DLT pushing
            throw ex;
        }
    }

    @KafkaListener(topics = "user-verification-topic", groupId = "notification-group")
    public void onVerificationRequested(String payload) throws Exception {
        UserVerificationRequested event = objectMapper.readValue(payload, UserVerificationRequested.class);
        Map<String, Object> model = new HashMap<>();
        model.put("Name", event.getFullName());
        model.put("otp", event.getOtp());
        Template t = config.getTemplate("Verify-Account-Otp.ftl");
        final String subject = "Your OTP Code for Account Verification";
        emailService.sendEmail(event.getEmail(), subject, t, model);
    }


}
