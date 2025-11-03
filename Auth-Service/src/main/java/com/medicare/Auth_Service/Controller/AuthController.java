package com.medicare.Auth_Service.Controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.medicare.Auth_Service.DTO.Request.SignInRequest;
import com.medicare.Auth_Service.DTO.Request.SignUpRequest;
import com.medicare.Auth_Service.DTO.Response.AuthResponse;
import com.medicare.Auth_Service.Services.AuthService;
import com.medicare.Auth_Service.Services.Schedule.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor // Use Lombok to inject AuthService
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;

    @PostMapping("/signUp")
    public ResponseEntity<String> signUpUser(@RequestBody SignUpRequest request) throws JsonProcessingException {
        String authResponse = authService.signUpUser(request);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/verify-User")
    public ResponseEntity<AuthResponse> verifyUser(@RequestParam String otp, @RequestParam String email, HttpServletResponse response) {
        AuthResponse authResponse = authService.verifyUser(otp, email, response);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/signIn")
    public ResponseEntity<AuthResponse> signInUser(@RequestBody SignInRequest request, HttpServletResponse response) {
        AuthResponse authResponse = authService.authenticate(request, response);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Boolean> forgotPassword(@RequestParam String email) {
        boolean sendOtp = authService.sendForgotPasswordOtp(email);
        return ResponseEntity.ok(sendOtp);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<Boolean> verifyOtp(@RequestParam String email, @RequestParam String otp) {
        boolean validOtp = authService.validateForgotPasswordOtp(email, otp);
        return ResponseEntity.ok(validOtp);
    }

    @PostMapping("/update-password")
    public ResponseEntity<String> updatePassword(@RequestParam String email, @RequestParam String password) {
        String msg = authService.updatePassword(password, email);
        return ResponseEntity.ok(msg);
    }

    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestParam String token) {
        boolean isValid = authService.isValid(token);
        return ResponseEntity.ok(isValid);
    }

    @PostMapping("/revokeUserToken")
    public ResponseEntity<String> revokeUserToken(HttpServletRequest request) {
        String res = tokenService.revokeAllUserTokens(request);
        return ResponseEntity.ok(res);
    }

    @SneakyThrows
    @PostMapping("/refreshToken")
    public ResponseEntity<HttpServletResponse> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        tokenService.refreshAccessToken(request, response);
        return ResponseEntity.ok(response);
    }

    @Profile("prod")
    @GetMapping("/google-login")
    public void googleLogin(HttpServletResponse response) throws IOException {
        // Redirect user to Spring Security's default OAuth2 login endpoint
        response.sendRedirect("http://localhost:8085/oauth2/authorization/google");
    }


    @GetMapping("/test")
    public ResponseEntity<?> test() {
        return ResponseEntity.ok("TEST");
    }
}
