package com.medicare.Auth_Service.Services.Oauth2_Service;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // Delegate to the default implementation for loading user info from Google
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Wrap into a custom object if you want (optional)
        return new CustomOAuth2User(oAuth2User.getAttributes());
    }
}
