package com.medicare.Auth_Service.Services;
import com.medicare.Auth_Service.Model.AccessToken;
import com.medicare.Auth_Service.Model.RefreshToken;
import com.medicare.Auth_Service.Repositories.AccessTokenRepository;
import com.medicare.Auth_Service.Repositories.RefreshTokenRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;
import jakarta.annotation.PostConstruct;

@Service
public class TokenCleanupService {

    private final AccessTokenRepository accessTokenRepo;
    private final RefreshTokenRepository refreshTokenRepo;
    private final JwtUtils jwtUtils;

    public TokenCleanupService(AccessTokenRepository accessTokenRepo,
                               RefreshTokenRepository refreshTokenRepo,
                               JwtUtils jwtUtils) {
        this.accessTokenRepo = accessTokenRepo;
        this.refreshTokenRepo = refreshTokenRepo;
        this.jwtUtils = jwtUtils;
    }

    // Run once at app startup
    @PostConstruct
    public void init() {
        try {
            deleteExpiredTokens();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage()+"------------------");
        }
    }


    // Run every 24 hour
    @Scheduled(fixedRate = 24 * 60 * 60 * 1000)
    public void deleteExpiredTokens() {
        List<AccessToken> expiredAccessTokens = new ArrayList<>();
        List<RefreshToken> expiredRefreshTokens = new ArrayList<>();

        accessTokenRepo.findAll().forEach(token -> {
            try {
                if (jwtUtils.isTokenExpired(token.getToken())) {
                    expiredAccessTokens.add(token);
                }
            } catch (Exception e) {
                System.err.println("❌ Error checking access token: " + e.getMessage());
                // Optionally: consider adding it to expired list anyway
            }
        });

        refreshTokenRepo.findAll().forEach(token -> {
            try {
                if (jwtUtils.isTokenExpired(token.getRefreshToken())) {
                    expiredRefreshTokens.add(token);
                }
            } catch (Exception e) {
                System.err.println("❌ Error checking refresh token: " + e.getMessage());
            }
        });

        accessTokenRepo.deleteAll(expiredAccessTokens);
        refreshTokenRepo.deleteAll(expiredRefreshTokens);

        System.out.println("✅ Expired tokens deleted at: " + new java.util.Date());
    }

}
