package com.medicare.Auth_Service.Services;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;

@Service
public class OtpService {
    private final StringRedisTemplate redis;
    private final SecureRandom random = new SecureRandom();
    private static final Duration OTP_TTL = Duration.ofMinutes(3);
    private static final int MAX_ATTEMPTS = 5;

    public OtpService(StringRedisTemplate redis) { this.redis = redis; }

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

        redis.opsForHash().putAll(key, payload);
        redis.expire(key, OTP_TTL);

        // TODO: integrate with SMS provider here (send `otp`)
        return sessionId; // return to client to bind verification
    }

    public boolean verify(String phone, String otp, String sessionId) {
        String key = "otp:" + phone;
        List<Object> vals = redis.opsForHash().multiGet(key, List.of("otp_hash", "attempts", "session_id"));
        if (vals == null || vals.get(0) == null) return false;

        String storedHash = (String) vals.get(0);
        int attempts = Integer.parseInt((String) (vals.get(1) == null ? "0" : vals.get(1)));
        String storedSession = (String) vals.get(2);

        if (!Objects.equals(storedSession, sessionId)) return false;
        if (attempts >= MAX_ATTEMPTS) return false;

        boolean ok = storedHash.equals(hashOtp(otp, sessionId));
        redis.opsForHash().put(key, "attempts", Integer.toString(attempts + 1));
        if (ok) redis.delete(key); // consume on success
        return ok;
    }

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
