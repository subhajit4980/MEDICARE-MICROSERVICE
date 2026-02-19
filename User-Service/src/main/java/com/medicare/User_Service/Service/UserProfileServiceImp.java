package com.medicare.User_Service.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medicare.User_Service.Events.UserRegisteredEvent;
import com.medicare.User_Service.Models.UserProfile;
import com.medicare.User_Service.Repository.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class UserProfileServiceImp implements UserProfileService {
    private final ObjectMapper objectMapper;
    private final UserProfileRepository userProfileRepository;

    @Override
    @KafkaListener(topics = "user-registered-topic", groupId = "user-group")
    public void addUserProfile(String payload, @Header(KafkaHeaders.RECEIVED_KEY) String key) {
        try {
            UserRegisteredEvent event = objectMapper.readValue(payload, UserRegisteredEvent.class);
            UserProfile userProfile=UserProfile.builder().userId(key).firstName(event.getFirstName()).lastName(event.getLastName()).createdAt(LocalDateTime.now()).build();
            userProfileRepository.save(userProfile);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
