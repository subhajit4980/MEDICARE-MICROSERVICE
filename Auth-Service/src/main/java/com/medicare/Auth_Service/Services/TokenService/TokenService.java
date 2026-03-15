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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final UserRepository repository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    ModelMapper modelMapper = new ModelMapper();

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    /**
     * Save refresh token in DB
     */
    public void saveUserToken(User user, String accessToken, String refreshToken) {

        log.info("Saving refresh token for userId={}", user.getUserId());

        Date now = new Date();
        Date refreshExp = Date.from(now.toInstant().plus(Duration.ofDays(7)));

        var rt = RefreshToken.builder()
                .user(user)
                .refreshToken(refreshToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .createdAt(now)
                .expiresAt(refreshExp)
                .build();

        refreshTokenRepository.save(rt);

        log.info("Refresh token stored successfully for userId={}", user.getUserId());
    }

    /**
     * Logout: revoke all tokens
     */
    @Transactional
    public String revokeAllUserTokens(HttpServletRequest request) {

        log.info("Logout requested");

        String refreshToken = getRefreshTokenFromCookie(request);

        if (refreshToken == null) {
            log.error("No refresh token found in cookie");
            throw new UserException(HttpStatus.UNAUTHORIZED, "Missing refresh token");
        }

        String userId;

        try {
            userId = jwtService.parseAndValidate(refreshToken).getSubject();
            log.info("Token belongs to userId={}", userId);
        } catch (Exception e) {
            log.error("Invalid refresh token: {}", e.getMessage());
            throw new UserException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
        }

        var refreshTokens = refreshTokenRepository.findRefreshTokensByUserId(userId);

        log.info("Revoking {} tokens for userId={}", refreshTokens.size(), userId);

        refreshTokens.forEach(t -> t.setRevoked(true));

        refreshTokenRepository.saveAll(refreshTokens);

        log.info("All tokens revoked successfully");

        return "All tokens revoked successfully";
    }

    /**
     * Refresh access token
     */
    @Transactional
    public void refreshAccessToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        log.info("Refresh token endpoint called");
        String refreshToken = getRefreshTokenFromCookie(request);
        if (refreshToken == null) {
            log.error("Missing refresh token in cookies");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing refresh token");
            return;
        }
        log.debug("Refresh token received");

        String userId;
        try {
            var claims = jwtService.parseAndValidate(refreshToken);
            if (!"refresh".equals(claims.getStringClaim("typ"))) {
                log.error("Wrong token type");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Wrong token type");
                return;
            }
            userId = claims.getSubject();
            log.info("Refresh token belongs to userId={}", userId);
        } catch (Exception e) {
            log.error("Refresh token validation failed: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid refresh token");
            return;
        }

        User user = repository.findUserByUserId(userId)
                .orElseThrow(() -> {
                    log.error("User not found in DB for userId={}", userId);
                    return new RuntimeException("User not found");
                });
        log.info("User loaded from DB");
        RefreshToken dbRt = refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> {
                    log.error("Refresh token not found in DB");
                    return new UserException(HttpStatus.UNAUTHORIZED, "Refresh not recognized");
                });

        if (dbRt.isRevoked() || dbRt.isExpired()) {
            log.warn("Refresh token is revoked or expired");
            revokeAllTokensForUser(user);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Refresh revoked/expired");
            return;
        }
        log.info("Starting refresh token rotation");
        String newAccess = jwtService.issueAccessToken(user);
        String newRefresh = jwtService.issueRefreshToken(user.getUserId());
        log.info("New tokens issued");
        saveUserToken(user, newAccess, newRefresh);
        log.info("New refresh cookie stored");
        storeRefreshCookie(newRefresh, response);
        log.info("Old refresh token revoked!!");
        dbRt.setRevoked(true);
        refreshTokenRepository.save(dbRt);
        UserDTO dto = modelMapper.map(user, UserDTO.class);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(
                response.getOutputStream(),
                AuthResponse.builder()
                        .accessToken(newAccess)
                        .user(dto)
                        .build()
        );

        log.info("Access token response sent");
    }

    /**
     * Revoke all tokens helper
     */
    private void revokeAllTokensForUser(User user) {

        log.info("Revoking all tokens for userId={}", user.getUserId());

        var rts = refreshTokenRepository.findRefreshTokensByUserId(user.getUserId());

        rts.forEach(t -> t.setRevoked(true));

        refreshTokenRepository.saveAll(rts);
    }

    /**
     * Store refresh cookie
     */
    public void storeRefreshCookie(String token, HttpServletResponse response) {

        log.info("Setting refresh cookie");

        Cookie refreshCookie = new Cookie("__Secure-med-srt", token);

        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge((int) Duration.ofDays(7).getSeconds());
        refreshCookie.setAttribute("SameSite", "Strict");

        response.addCookie(refreshCookie);

        log.info("Refresh cookie added to response");
    }

    /**
     * Extract refresh token from cookies
     */
    public String getRefreshTokenFromCookie(HttpServletRequest request) {

        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            log.warn("No cookies found in request");
            return null;
        }

        log.debug("Total cookies received: {}", cookies.length);

        for (Cookie c : cookies) {

            log.debug("Cookie detected -> {}", c.getName());

            if ("__Secure-med-srt".equals(c.getName())) {

                log.info("Refresh cookie found");

                return c.getValue();
            }
        }

        log.warn("Refresh cookie not found");

        return null;
    }
}