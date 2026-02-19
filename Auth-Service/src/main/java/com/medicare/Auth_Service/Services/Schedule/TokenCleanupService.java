package com.medicare.Auth_Service.Services.Schedule;

import com.medicare.Auth_Service.Model.RefreshToken;
import com.medicare.Auth_Service.Repositories.RefreshTokenRepository;
import com.medicare.Auth_Service.Services.TokenService.JwtService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Service responsible for cleaning up expired access and refresh tokens.
 * Runs automatically at startup and every 24 hours.
 */
@RequiredArgsConstructor
@Service
public class TokenCleanupService {

    private final RefreshTokenRepository refreshTokenRepo;
    private final JwtService jwtService; // utility class to validate token expiry

    // Constructor injection for repositories + jwt service
//    public TokenCleanupService(
//                               RefreshTokenRepository refreshTokenRepo,
//                               JwtService jwtService) {
//        this.refreshTokenRepo = refreshTokenRepo;
//        this.jwtService = jwtService;
//    }

    /**
     * Executes once right after the application starts.
     * Ensures no expired tokens remain in DB from before.
     */
    @PostConstruct
    public void init() {
        try {
            deleteExpiredTokens();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Init cleanup error: " + e.getMessage());
        }
    }

    /**
     * Runs periodically (every 24 hours).
     * - Collects all expired refresh tokens.
     * - Deletes them from the database.
     */
    @Scheduled(fixedRate = 24 * 60 * 60 * 1000) // 24 hours in milliseconds
    public void deleteExpiredTokens() {
        // Lists to store tokens that are expired
        List<RefreshToken> expiredRefreshTokens = new ArrayList<>();

        // --- Check refresh tokens ---
        refreshTokenRepo.findAll().forEach(token -> {
            try {
                // If expired → add to deletion list
                if (jwtService.isExpiredToken(token.getRefreshToken())) {
                    expiredRefreshTokens.add(token);
                }
            } catch (Exception e) {
                System.err.println("❌ Error checking refresh token: " + e.getMessage());
            }
        });

        // --- Delete expired tokens ---
        if (!expiredRefreshTokens.isEmpty()) {
            refreshTokenRepo.deleteAll(expiredRefreshTokens);
            System.out.println("🗑️ Deleted " + expiredRefreshTokens.size() + " expired refresh tokens");
        }

        System.out.println("✅ Token cleanup run completed at: " + new java.util.Date());
    }
}
