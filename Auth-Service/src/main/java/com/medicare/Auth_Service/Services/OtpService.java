package com.medicare.Auth_Service.Services;

import com.medicare.Auth_Service.DTO.Request.OtpVerifyRequest;
import lombok.RequiredArgsConstructor;
//import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;

@Service
@RequiredArgsConstructor
public class OtpService {
//    private final StringRedisTemplate redis;
    private final NotificationClient notificationClient;
    private final SecureRandom random = new SecureRandom();
    private static final Duration OTP_TTL = Duration.ofMinutes(3);
    private static final int MAX_ATTEMPTS = 5;

//    public OtpService(StringRedisTemplate redis, NotificationClient notificationClient) { this.redis = redis;
//        this.notificationClient = notificationClient;
//    }

    public String requestOtp(String phone) {
        String otp = String.format("%06d", random.nextInt(1_000_000));
        String sessionId = UUID.randomUUID().toString();

        String key = "otp:" + phone;
        String otpHash = hashOtp(otp, sessionId);

        Map<String, String> payload = new HashMap<>();
        payload.put("otp_hash", otpHash);
        payload.put("attempts", "0");
        payload.put("session_id", sessionId);
        payload.put("created_at", Long.toString(System.currentTimeMillis()));

//        redis.opsForHash().putAll(key, payload);
//        redis.expire(key, OTP_TTL);
        // ✅ SMS Template
        String message = String.format(
                "Medicare verification code: %s.\nValid for 3 minutes. Never share this code.",
                otp
        );
        // TODO: integrate with SMS provider here (send `otp`)
        notificationClient.sendSms(phone,message);
        return sessionId; // return to client to bind verification
    }

//    public boolean verify(OtpVerifyRequest otpVerifyRequest) {
//        String key = "otp:" + otpVerifyRequest.getPhone();
//        List<Object> vals = redis.opsForHash().multiGet(key, List.of("otp_hash", "attempts", "session_id"));
//        if (vals == null || vals.get(0) == null) return false;
//
//        String storedHash = (String) vals.get(0);
//        int attempts = Integer.parseInt((String) (vals.get(1) == null ? "0" : vals.get(1)));
//        String storedSession = (String) vals.get(2);
//
//        if (!Objects.equals(storedSession, otpVerifyRequest.getSessionId())) return false;
//        if (attempts >= MAX_ATTEMPTS) return false;
//
//        boolean ok = storedHash.equals(hashOtp(otpVerifyRequest.getOtp(), otpVerifyRequest.getSessionId()));
//        redis.opsForHash().put(key, "attempts", Integer.toString(attempts + 1));
//        if (ok) redis.delete(key); // consume on success
//        return ok;
//    }

    private String hashOtp(String otp, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] out = md.digest(otp.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(out);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
