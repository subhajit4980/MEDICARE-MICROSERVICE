package com.medicare.Auth_Service.Services.Oauth2_Service;


import com.medicare.Auth_Service.Services.JwtUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtils jwtUtil;



    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getEmail();
        String name = oAuth2User.getName();

        // Generate your own JWT for the user
        String token = jwtUtil.generateTokenForOauth2(email,name);

        // Return it to frontend (for simplicity in response body)
        response.setContentType("application/json");
        response.getWriter().write("{\"jwt\": \"" + token + "\"}");
    }
}
