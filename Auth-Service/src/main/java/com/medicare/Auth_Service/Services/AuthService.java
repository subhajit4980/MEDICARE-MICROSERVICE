package com.medicare.Auth_Service.Services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medicare.Auth_Service.DTO.Request.SignInRequest;
import com.medicare.Auth_Service.DTO.Request.SignUpRequest;
import com.medicare.Auth_Service.DTO.Response.AuthResponse;
import com.medicare.Auth_Service.DTO.Response.AuthResult;
import com.medicare.Auth_Service.DTO.Response.UserDTO;
import com.medicare.Auth_Service.Events.OutboxEvent;
import com.medicare.Auth_Service.Events.UserRegisteredEvent;
import com.medicare.Auth_Service.Events.UserVerificationRequested;
import com.medicare.Auth_Service.Exception.UserException;
import com.medicare.Auth_Service.Model.Enum.Role;
import com.medicare.Auth_Service.Model.User;
import com.medicare.Auth_Service.Repositories.AccessTokenRepository;
import com.medicare.Auth_Service.Repositories.OutboxRepository;
import com.medicare.Auth_Service.Repositories.RefreshTokenRepository;
import com.medicare.Auth_Service.Repositories.UserRepository;
import com.medicare.Auth_Service.Services.TokenService.JwtService;
import com.medicare.Auth_Service.Services.TokenService.TokenService;
import com.medicare.Auth_Service.Utils.Common;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.data.mongodb.MongoTransactionManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthService {

    // Dependencies injected via constructor
    private final UserRepository repository;
    private final AccessTokenRepository accessTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final OutboxRepository outboxRepository;
    private final PasswordEncoder encoder;
    private final JwtService jwtService;                 // Service for JWT issue/validation
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    ModelMapper modelMapper = new ModelMapper();
    private final RedisTemplate<String, Object> redisTemplate;
    private final KafkaTemplate kafkaTemplate;
    private final ObjectMapper objectMapper;
    private final UserRegistrationService userRegistrationService;

    /**
     * SIGNUP METHOD
     * Registers a new user, validates password & email,
     * saves in DB, issues JWT tokens (access + refresh).
     */
    @Transactional
    public String signUpUser(SignUpRequest request) throws JsonProcessingException {
        // Normalize email (trim & lowercase)
        String norm = request.getEmail().trim().toLowerCase(Locale.ROOT);

        // Validate email
        if (!norm.contains("@")) throw new UserException(HttpStatus.BAD_REQUEST, "Email is not valid");
        if (repository.existsByEmail(norm)) throw new UserException(HttpStatus.CONFLICT, "User already registered");

        // Password validation rules
        var charlist = Common.validatePassword(request.getPassword());
        if (request.getPassword().length() < 8)
            throw new UserException(HttpStatus.NOT_ACCEPTABLE, "Password length must be >= 8");
        if (request.getPassword().contains(" "))
            throw new UserException(HttpStatus.NOT_ACCEPTABLE, "Password must not contain spaces");
        if (!charlist.isEmpty())
            throw new UserException(HttpStatus.NOT_ACCEPTABLE, "Password invalid: " + charlist);

        // Create user object
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(norm)
                .password(encoder.encode(request.getPassword()))   // encrypt password
                .creationDate(new Date())
                .verified(false)
                .role(request.getRole() != null ? request.getRole() : Role.USER)
                .build();
//        Store the user data in redis temporarily
        redisTemplate.opsForValue().set(norm, user, 60, TimeUnit.MINUTES);
        String otp = Common.generateOTP();
        redisTemplate.opsForValue().set(norm + "_otp", otp, 5, TimeUnit.MINUTES);
        UserVerificationRequested event = new UserVerificationRequested(
                otp,
                request.getFirstName() + " " + request.getLastName(),
                norm
        );
        kafkaTemplate.send("user-verification-topic", objectMapper.writeValueAsString(event));
        // Return response
        return "Verification mail send";
    }

    @Transactional
    public AuthResponse verifyUser(String otp, String email, HttpServletResponse response) {
        String otp_ = Objects.requireNonNull(redisTemplate.opsForValue().get(email + "_otp")).toString();
        AuthResult authResult;
        // Save user + outbox in a single MongoDB transaction
        if (otp.equals(otp_)) {
            authResult = userRegistrationService.finalizeRegistration(email, response);
        } else
            throw new UserException(HttpStatus.REQUEST_TIMEOUT, "OTP is not a valid");
        redisTemplate.delete(email + "_otp");
        UserDTO dto = modelMapper.map(authResult.getUser(), UserDTO.class);
        return AuthResponse.builder().accessToken(authResult.getAccessToken()).user(dto).build();
    }


    /**
     * LOGIN METHOD
     * Authenticates existing user and issues fresh tokens.
     */
    @Transactional(readOnly = true,transactionManager ="transactionManager")
    public AuthResponse authenticate(SignInRequest request, HttpServletResponse response) {
        String norm = request.getEmail().trim().toLowerCase(Locale.ROOT);

        // Check user exists
        User user = repository.findByEmail(norm)
                .orElseThrow(() -> new UserException(HttpStatus.BAD_REQUEST, "Email is not registered"));

        // Authenticate credentials using Spring Security
        Authentication auth = authentication(norm, request.getPassword());
        if (!auth.isAuthenticated()) throw new UserException(HttpStatus.BAD_REQUEST, "Wrong Credentials Provided");

        // Generate tokens
        String access = jwtService.issueAccessToken(user);
        String refresh = jwtService.issueRefreshToken(user.getUserId());

        // Save + set refresh cookie
        tokenService.saveUserToken(user, access, refresh);
        tokenService.storeRefreshCookie(refresh, response);
        UserDTO dto = modelMapper.map(user, UserDTO.class);
        return AuthResponse.builder().accessToken(access).user(dto).build();
    }

    /**
     * AUTHENTICATION HELPER
     * Uses Spring Security's AuthenticationManager to check username+password.
     */
    public Authentication authentication(String email, String password) {
        Authentication pre = new UsernamePasswordAuthenticationToken(email, password);
        try {
            Authentication authentication = authenticationManager.authenticate(pre); // actual check
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return authentication;
        } catch (org.springframework.security.core.AuthenticationException e) {
            throw new UserException(HttpStatus.BAD_REQUEST, "Wrong Credentials Provided");
        }
    }

    /**
     * VALIDATION METHOD
     * Just validates token structure & signature (basic check).
     * Deep access control is handled at API Gateway.
     */
    public boolean isValid(String token) {
        try {
            jwtService.parseAndValidate(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * LOGOUT METHOD
     * Revokes user tokens + clears refresh cookie.
     */
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        // Revoke all active tokens for this user (optional)
        try {
            tokenService.revokeAllUserTokens(request);
        } catch (Exception ignored) {
        }

        // Delete refresh token cookie
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);    // prevent JS access
        cookie.setSecure(true);      // only HTTPS
        cookie.setPath("/");         // valid for entire domain
        cookie.setMaxAge(0);         // expire immediately
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);

        return ResponseEntity.ok("Logged out successfully");
    }
}
