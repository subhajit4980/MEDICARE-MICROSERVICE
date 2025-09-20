package com.medicare.Auth_Service.Services.Oauth2_Service;

import com.medicare.Auth_Service.DTO.Response.AuthResult;
import com.medicare.Auth_Service.Model.Enum.Role;
import com.medicare.Auth_Service.Model.User;
import com.medicare.Auth_Service.Repositories.UserRepository;
import com.medicare.Auth_Service.Services.TokenService.JwtService;
import com.medicare.Auth_Service.Services.Schedule.TokenService;
import com.medicare.Auth_Service.Services.UserRegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final TokenService tokenService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final UserRegistrationService userRegistrationService;

    /**
     * This method gets called automatically when
     * OAuth2 login is successful (e.g., Google Login).
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        // Extract OAuth2 user info from authentication
        OAuth2User oauth = (OAuth2User) authentication.getPrincipal();
        String email = oauth.getAttribute("email");
        String sub = oauth.getAttribute("sub");  // Google unique user ID
        String norm = email.trim().toLowerCase(Locale.ROOT); // normalize email
        String firstName = oauth.getAttribute("given_name");
        String lastName = oauth.getAttribute("family_name");
        // Check if user exists in DB, else create new
        AuthResult authResult = userRepository.findByEmail(norm)
                .map(u -> new AuthResult(u, jwtService.issueAccessToken(u)))
                .orElseGet(() -> {
                    User u = new User();
                    u.setEmail(norm);
                    u.setFirstName(firstName);
                    u.setLastName(lastName);
                    // Assign default role if null
                    if (u.getRole() == null) {
                        u.setRole(Role.USER);
                    }
                    u.setGoogleSub(sub);
                    redisTemplate.opsForValue().set(norm, u, 60, TimeUnit.MINUTES);
                    return userRegistrationService.finalizeRegistration(norm, response);
                });
        response.setContentType("application/json");
        response.getWriter().write("{\"accessToken\":\"" + authResult.getAccessToken() + "\"}");
    }
}
