package com.medicare.Auth_Service.Services.TokenService;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medicare.Auth_Service.DTO.Response.AuthResponse;
import com.medicare.Auth_Service.DTO.Response.UserDTO;
import com.medicare.Auth_Service.Exception.UserException;
import com.medicare.Auth_Service.Model.Enum.TokenType;
import com.medicare.Auth_Service.Model.RefreshToken;
import com.medicare.Auth_Service.Model.User;
import com.medicare.Auth_Service.Repositories.RefreshTokenRepository;
import com.medicare.Auth_Service.Repositories.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class TokenService {

    // === Dependencies injected by Spring ===
    private final UserRepository repository;
    private final RefreshTokenRepository refreshTokenRepository;   // Repo for refresh tokens
    private final JwtService jwtService;                           // Service to issue & validate JWTs (RS256)
    ModelMapper modelMapper = new ModelMapper();                   // Mapper for DTOs (not used much here)

    /**
     * Save tokens (currently only refresh token stored in DB).
     */
    public void saveUserToken(User user, String accessToken, String refreshToken) {
        Date now = new Date();
        Date refreshExp = Date.from(new Date().toInstant().plus(Duration.ofDays(7)));


        // Save refresh token in DB
        var rt = RefreshToken.builder()
                .user(user)
                .refreshToken(refreshToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .createdAt(now)
                .expiresAt(refreshExp)
                .build();
        //
        refreshTokenRepository.save(rt);
    }

    /**
     * Revoke all tokens (called e.g. during logout).
     */
    @Transactional
    public String revokeAllUserTokens(HttpServletRequest request) {
        String refreshToken = getRefreshTokenFromCookie(request);
        if (refreshToken == null) {
            throw new UserException(HttpStatus.UNAUTHORIZED, "Missing refresh token");
        }

        String userId;
        try {
            // Parse refresh token and extract userId (subject)
            userId = jwtService.parseAndValidate(refreshToken).getSubject();
        } catch (Exception e) {
            throw new UserException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
        }

        // Find all refresh tokens belonging to this user
        var refreshTokens = refreshTokenRepository.findRefreshTokensByUserId(userId);

        // Revoke them
        refreshTokens.forEach(t -> t.setRevoked(true));

        // Save back to DB
        refreshTokenRepository.saveAll(refreshTokens);

        return "All tokens revoked successfully";
    }

    /**
     * Rotate tokens and issue a new access + refresh when access expires.
     */
    @Transactional
    public void refreshAccessToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String refreshToken = getRefreshTokenFromCookie(request);
        if (refreshToken == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing refresh token");
            return;
        }

        String userId;
        try {
            var claims = jwtService.parseAndValidate(refreshToken);

            // Ensure this token is of type "refresh"
            if (!"refresh".equals(claims.getStringClaim("typ"))) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Wrong token type");
                return;
            }
            userId = claims.getSubject();
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid refresh token");
            return;
        }

        // Fetch user from DB
        User user = repository.findUserByUserId(userId).orElseThrow();

        // Validate refresh token in DB
        RefreshToken dbRt = refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new UserException(HttpStatus.UNAUTHORIZED, "Refresh not recognized"));

        if (dbRt.isRevoked() || dbRt.isExpired()) {
            // If token is revoked or expired -> kill all user tokens and reject
            revokeAllTokensForUser(user);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Refresh revoked/expired");
            return;
        }

        // === Refresh rotation ===
        // Old refresh token is revoked
        dbRt.setRevoked(true);
        refreshTokenRepository.save(dbRt);

        // Issue new tokens
        String newAccess = jwtService.issueAccessToken(user);
        String newRefresh = jwtService.issueRefreshToken(user.getUserId());

        // Store in DB
        saveUserToken(user, newAccess, newRefresh);

        // Send refresh token as cookie
        storeRefreshCookie(newRefresh, response);
        UserDTO dto = modelMapper.map(user, UserDTO.class);
        // Send access token in response body
        new ObjectMapper().writeValue(response.getOutputStream(),
                AuthResponse.builder().accessToken(newAccess).user(dto).build());
    }

    /**
     * Revoke all tokens for a given user (helper).
     */
    private void revokeAllTokensForUser(User user) {
        var rts = refreshTokenRepository.findRefreshTokensByUserId(user.getUserId());
        rts.forEach(t -> t.setRevoked(true));
        refreshTokenRepository.saveAll(rts);
    }

    /**
     * Store refresh token securely as HttpOnly cookie.
     */
    public void storeRefreshCookie(String token, HttpServletResponse response) {
        Cookie refreshCookie = new Cookie("__Secure-med-srt", token);
        refreshCookie.setHttpOnly(true);                       // Prevent JavaScript access
        refreshCookie.setSecure(true);                         // Send only over HTTPS
        refreshCookie.setPath("/auth/refresh");                            // Cookie valid across all endpoints
        refreshCookie.setMaxAge((int) Duration.ofDays(7).getSeconds());  // Expiration
        refreshCookie.setAttribute("SameSite", "Strict");      // CSRF protection
        response.addCookie(refreshCookie);
    }

    /**
     * Extract refresh token from cookies.
     */
    public String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if ("__Secure-med-srt".equals(c.getName())) return c.getValue();
            }
        }
        return null;
    }
}
