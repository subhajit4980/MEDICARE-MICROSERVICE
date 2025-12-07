package com.medicare.Auth_Service.Services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medicare.Auth_Service.DTO.Response.AuthResult;
import com.medicare.Auth_Service.Events.OutboxEvent;
import com.medicare.Auth_Service.Events.UserRegisteredEvent;
import com.medicare.Auth_Service.Exception.UserException;
import com.medicare.Auth_Service.Model.User;
import com.medicare.Auth_Service.Repositories.OutboxRepository;
import com.medicare.Auth_Service.Repositories.UserRepository;
import com.medicare.Auth_Service.Services.TokenService.JwtService;
import com.medicare.Auth_Service.Services.Schedule.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.mongodb.MongoTransactionManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

@Service
@RequiredArgsConstructor
public class UserRegistrationService {

    private final UserRepository repository;
    private final OutboxRepository outboxRepository;
    private final JwtService jwtService;
    private final TokenService tokenService;
    private final ObjectMapper objectMapper;
    private final MongoTransactionManager txManager;
    private final RedisTemplate<String, Object> redisTemplate;

    @Transactional
    public AuthResult finalizeRegistration(String email, HttpServletResponse response) {
        TransactionTemplate txTemplate = new TransactionTemplate(txManager);

        return txTemplate.execute(status -> {

            User user = (User) redisTemplate.opsForValue().get(email);
            if (user == null) {
                // UPDATED: throw UserException instead of RuntimeException
                throw new UserException(
                        HttpStatus.NOT_FOUND,
                        "User data not found in Redis",
                        "AUTH_USER_NOT_FOUND"
                );
            }

            // Mark user as verified
            user.setVerified(true);

            // Save to MongoDB
            User saved = repository.save(user);

            // Issue JWT tokens
            String refresh = jwtService.issueRefreshToken(saved.getUserId());
            String access = jwtService.issueAccessToken(saved);

            // Persist tokens + cookie
            tokenService.saveUserToken(saved, access, refresh);
            tokenService.storeRefreshCookie(refresh, response);

            // Publish outbox event
            try {
                UserRegisteredEvent payload = new UserRegisteredEvent(
                        saved.getUserId(),
                        saved.getEmail(),
                        saved.getFirstName() + " " + saved.getLastName()
                );

                String json = objectMapper.writeValueAsString(payload);

                OutboxEvent ev = new OutboxEvent();
                ev.setAggregateId(saved.getUserId());
                ev.setEventType("USER_REGISTERED");
                ev.setPayload(json);

                outboxRepository.save(ev);
                redisTemplate.delete(email);

            } catch (JsonProcessingException e) {

                // UPDATED: replaced RuntimeException with UserException
                throw new UserException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to serialize event payload",
                        "AUTH_OUTBOX_SERIALIZATION_ERROR"
                );
            }

            return new AuthResult(saved, access);
        });
    }
}
