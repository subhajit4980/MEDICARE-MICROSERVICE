package com.medicare.Auth_Service.Controller;

import com.medicare.Auth_Service.DTO.Request.ValidateRequest;
import com.medicare.Auth_Service.DTO.Response.AuthResponse;
import com.medicare.Auth_Service.DTO.Request.SignInRequest;
import com.medicare.Auth_Service.DTO.Request.SignUpRequest;
import com.medicare.Auth_Service.Services.AuthService;
import com.medicare.Auth_Service.Services.TokenService.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor // Use Lombok to inject AuthService
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;

    @PostMapping("/signUp")
    public ResponseEntity<AuthResponse> signUpUser(
            @RequestBody SignUpRequest request,
            HttpServletResponse response) {
        AuthResponse authResponse = authService.signUpUser(request, response);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/signIn")
    public ResponseEntity<AuthResponse> signInUser(
            @RequestBody SignInRequest request,
            HttpServletResponse response) {
        AuthResponse authResponse = authService.authenticate(request, response);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestParam String token) {
        boolean isValid = authService.isValid(token);
        return ResponseEntity.ok(isValid);
    }
    @PostMapping("/revokeUserToken")
    public ResponseEntity<String> revokeUserToken(HttpServletRequest request)
    {
           String res= tokenService.revokeAllUserTokens(request);
            return ResponseEntity.ok(res);
    }
    @GetMapping("/google-login")
    public void googleLogin(HttpServletResponse response) throws IOException {
        // Redirect user to Spring Security's default OAuth2 login endpoint
        response.sendRedirect("/oauth2/authorization/google");
        }
    @GetMapping("/test")
    public ResponseEntity<?> test()
    {
        return ResponseEntity.ok("TEST");
    }
}
