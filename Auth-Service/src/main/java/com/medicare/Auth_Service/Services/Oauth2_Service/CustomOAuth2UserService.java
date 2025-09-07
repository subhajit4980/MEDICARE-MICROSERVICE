package com.medicare.Auth_Service.Services.Oauth2_Service;

import com.medicare.Auth_Service.Model.User;
import com.medicare.Auth_Service.Repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Locale;


@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest req) throws OAuth2AuthenticationException {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User user = delegate.loadUser(req);

        String email = user.<String>getAttribute("email");
        String sub = user.<String>getAttribute("sub");
        String firstName = user.<String>getAttribute("given_name");
        String lastName = user.<String>getAttribute("family_name");

        if (email == null)
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_userinfo"), "Email missing");

        String norm = email.trim().toLowerCase(Locale.ROOT);

        User entity = userRepository.findByEmail(norm).orElseGet(() -> {
            User u = new User();
            u.setEmail(norm);
            u.setVerified(true);
            u.setFirstName(firstName);
            u.setLastName(lastName);
            // default role if null
            if (u.getRole() == null) {
                u.setRole(com.medicare.Auth_Service.Model.Enum.Role.USER);
            }
            return u;
        });

        // If you add a googleSub column to User, set it here:
        entity.setGoogleSub(sub);
        System.out.println(sub);
        userRepository.save(entity);
        return user; // Spring will pass this to successHandler
    }
}