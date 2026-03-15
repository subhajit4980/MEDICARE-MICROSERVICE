package com.medicare.User_Service.listener;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medicare.User_Service.Events.UserRegisteredEvent;
import com.medicare.User_Service.Model.UserProfile;
import com.medicare.User_Service.Repository.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
@Service
@RequiredArgsConstructor
public class UserRegisteredListener {
    private static final Logger log = LoggerFactory.getLogger(UserRegisteredListener.class);

    private final ObjectMapper objectMapper;
    private final UserProfileRepository userProfileRepository;

    @KafkaListener(topics = "user-registered-topic", groupId = "user-group")
    public void addUserProfile(String payload, @Header(KafkaHeaders.RECEIVED_KEY) String key) {
        try {
            log.debug("Received user-registered event for userId={}", key);
            UserRegisteredEvent event = objectMapper.readValue(payload, UserRegisteredEvent.class);
            UserProfile userProfile=UserProfile.builder().userId(key).firstName(event.getFirstName()).lastName(event.getLastName()).createdAt(LocalDateTime.now()).build();
            userProfileRepository.save(userProfile);
        } catch (Exception e) {
            log.error("Failed to process user-registered event for key={}", key, e);
            throw new RuntimeException(e);
        }

    }
}
