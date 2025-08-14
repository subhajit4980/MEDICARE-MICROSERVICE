package com.medicare.Auth_Service.Services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medicare.Auth_Service.DTO.Request.ValidateRequest;
import com.medicare.Auth_Service.DTO.Response.AuthResponse;
import com.medicare.Auth_Service.DTO.Request.SignInRequest;
import com.medicare.Auth_Service.DTO.Request.SignUpRequest;
import com.medicare.Auth_Service.Exception.UserException;
import com.medicare.Auth_Service.Model.Enum.TokenType;
import com.medicare.Auth_Service.Model.AccessToken;
import com.medicare.Auth_Service.Model.RefreshToken;
import com.medicare.Auth_Service.Model.User;
import com.medicare.Auth_Service.Repositories.AccessTokenRepository;
import com.medicare.Auth_Service.Repositories.RefreshTokenRepository;
import com.medicare.Auth_Service.Repositories.UserRepository;
import com.medicare.Auth_Service.Utils.Common;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
@Service
@RequiredArgsConstructor
public class AuthService {
    // === Dependencies ===
    private final UserRepository repository;
    private final AccessTokenRepository accessTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    ModelMapper modelMapper = new ModelMapper();

    /**
     * Registers a new user after validating email, password and saving tokens.
     */
    @Transactional
    public AuthResponse signUpUser(SignUpRequest request, HttpServletResponse response) {
        // ✅ Validate email format
        if (!request.getEmail().contains("@gmail.com"))
            throw new UserException(HttpStatus.BAD_REQUEST, "Email is not valid");

        // ✅ Check if email is already registered
        if (repository.existsByEmail(request.getEmail().toUpperCase(Locale.ROOT)))
            throw new UserException(HttpStatus.CONFLICT, "User already registered");

        // ✅ Validate password strength
        var charlist = Common.validatePassword(request.getPassword());
        if (request.getPassword().length() < 8)
            throw new UserException(HttpStatus.BAD_REQUEST, "Password length must be greater than 8 characters");

        if (!charlist.isEmpty())
            throw new UserException(HttpStatus.BAD_REQUEST, "Password is invalid. Missing character types: " + charlist);

        // ✅ Create and save user
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail().toUpperCase(Locale.ROOT))
                .password(encoder.encode(request.getPassword()))
                .creationDate(new Date())
                .verified(false)
                .role(request.getRole())
                .build();

        var savedUser = repository.save(user);

        // ✅ Generate tokens
        var accessToken = jwtUtils.generateToken(new CustomUserDetails(user));
        var refreshToken = jwtUtils.generateRefreshToken(new CustomUserDetails(user),savedUser.getUserId());

        // ✅ Save tokens in DB
        saveUserToken(savedUser, accessToken, refreshToken);

        // ✅ Store refresh token in HttpOnly cookie
        storeCookie(refreshToken, response);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .user(savedUser)
                .build();
    }

    /**
     * Authenticates a user with credentials, sets cookie and returns access token.
     */
    @Transactional(readOnly = true)
    public AuthResponse authenticate(SignInRequest request, HttpServletResponse response) {
        String email = request.getEmail().trim().toLowerCase(Locale.ROOT);

        // ✅ Validate email domain
        if (!email.endsWith("@gmail.com")) {
            throw new UserException(HttpStatus.BAD_REQUEST, "Email must be a valid Gmail address");
        }

        // ✅ Fetch user by email
        var user = repository.findByEmail(email.toUpperCase(Locale.ROOT))
                .orElseThrow(() -> new UserException(HttpStatus.BAD_REQUEST, "Email is not registered"));

        // ✅ Authenticate using Spring Security
        Authentication authentication = authentication(email.toUpperCase(Locale.ROOT), request.getPassword());
        if (!authentication.isAuthenticated()) {
            throw new UserException(HttpStatus.BAD_REQUEST, "Wrong Credentials Provided");
        }

        // ✅ Generate new tokens
        CustomUserDetails userDetails = new CustomUserDetails(user);
        String accessToken = jwtUtils.generateToken(userDetails);
        String refreshToken = jwtUtils.generateRefreshToken(userDetails, user.getUserId());

        // ✅ Save in DB
        saveUserToken(user, accessToken, refreshToken);

        // ✅ Set refresh token cookie
        storeCookie(refreshToken, response);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .user(user)
                .build();
    }

    /**
     * Uses Spring AuthenticationManager to authenticate user credentials.
     */
    public Authentication authentication(String email, String password) {
        Authentication auth = new UsernamePasswordAuthenticationToken(email.toUpperCase(Locale.ROOT), password);
        try {
            Authentication authentication = authenticationManager.authenticate(auth);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return authentication;
        } catch (org.springframework.security.core.AuthenticationException e) {
            throw new UserException(HttpStatus.BAD_REQUEST, "Wrong Credentials Provided");
        }
    }

    /**
     * Validates a token using model mapping and utility.
     */
    public boolean isValid(ValidateRequest validateRequest) {
        CustomUserDetails customUserDetails = modelMapper.map(validateRequest, CustomUserDetails.class);
        return !jwtUtils.isTokenExpired(validateRequest.getToken()) &&
                jwtUtils.isTokenValid(validateRequest.getToken(), customUserDetails);
    }

    /**
     * Persists new access and refresh tokens in DB.
     */
    private void saveUserToken(User user, String accessToken, String refreshToken) {
        var now = new Date();
        var expiry = new Date(now.getTime() + jwtUtils.refresh_token_expiration);
        var expiryAccessToken = new Date(now.getTime() + jwtUtils.jwtExpirationMs);

        var token1 = AccessToken.builder()
                .user(user)
                .token(accessToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .createdAt(now)
                .expiresAt(expiryAccessToken)
                .build();

        accessTokenRepository.save(token1);

        var token2 = RefreshToken.builder()
                .user(user)
                .refreshToken(refreshToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .createdAt(now)
                .expiresAt(expiry)
                .build();
        refreshTokenRepository.save(token2);
    }

    /**
     * Revokes all access and refresh tokens for the user.
     */
    @Transactional
    public String revokeAllUserTokens(HttpServletRequest request) {
        String refreshToken = getRefreshTokenFromCookie(request);

        if (refreshToken == null || jwtUtils.isTokenExpired(refreshToken)) {
            throw new UserException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
        }

        String userId;
        try {
            userId = jwtUtils.getUserIdFromJwtToken(refreshToken);
        } catch (Exception e) {
            throw new UserException(HttpStatus.UNAUTHORIZED, "Invalid token payload");
        }

        var validUserAccessTokens = accessTokenRepository.findTokensByUserId(userId);
        var validUserRefreshTokens = refreshTokenRepository.findRefreshTokensByUserId(userId);

        if (validUserAccessTokens.isEmpty() && validUserRefreshTokens.isEmpty()) {
            throw new UserException(HttpStatus.NOT_FOUND, "No active tokens found for user");
        }

        validUserAccessTokens.forEach(token -> token.setRevoked(true));
        validUserRefreshTokens.forEach(token -> token.setRevoked(true));

        accessTokenRepository.saveAll(validUserAccessTokens);
        refreshTokenRepository.saveAll(validUserRefreshTokens);

        return "All tokens revoked successfully";
    }


    /**
     * Refreshes access token using a valid refresh token stored in cookie.
     */
    public void refreshAccessToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String userEmail;
        String refreshToken = null;

        // ✅ Extract refresh token from cookie
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        if (refreshToken == null || !jwtUtils.validateJwtToken(refreshToken)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or missing refresh token");
            return;
        }

        userEmail = jwtUtils.getEmailFromJwtToken(refreshToken);
        if (userEmail != null) {
            var user = repository.findByEmail(userEmail).orElseThrow();
            RefreshToken refToken = refreshTokenRepository.findByRefreshToken(refreshToken).orElseThrow();

            if (!refToken.isExpired() && !refToken.isRevoked()) {
                // ✅ Generate new access token
                var accessToken = jwtUtils.generateToken(new CustomUserDetails(user));

                // ✅ Revoke old tokens
                revokeAllUserTokens(request);

                // ✅ Save new access token only
                var now = new Date();
                var expiry = new Date(now.getTime() + jwtUtils.refresh_token_expiration);

                var token = AccessToken.builder()
                        .user(user)
                        .token(accessToken)
                        .tokenType(TokenType.BEARER)
                        .expired(false)
                        .revoked(false)
                        .createdAt((java.sql.Date) now)
                        .expiresAt((java.sql.Date) expiry)
                        .build();

                accessTokenRepository.save(token);

                // ✅ Return access token in body
                var authResponse = AuthResponse.builder()
                        .accessToken(accessToken)
                        .build();

                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    /**
     * Logs user out by revoking tokens and clearing cookie.
     */
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        String userEmail = jwtUtils.getEmailFromJwtToken(getAccessTokenFromHeader(request));
        if (userEmail != null) {
            var user = repository.findByEmail(userEmail).orElse(null);
            if (user != null) revokeAllUserTokens(request);
        }

        // ✅ Remove refresh token cookie
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return ResponseEntity.ok("Logged out successfully");
    }

    /**
     * Extracts access token from Authorization header.
     */
    private String getAccessTokenFromHeader(HttpServletRequest request) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Stores refresh token as HttpOnly cookie in the response.
     */
    private void storeCookie(String token, HttpServletResponse response) {
        Cookie refreshCookie = new Cookie("refreshToken", token);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
        response.addCookie(refreshCookie);
    }
    public String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

}
