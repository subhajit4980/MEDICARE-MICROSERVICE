package com.medicare.Auth_Service.Config;

import com.medicare.Auth_Service.Services.TokenService.AuthEntryPointJwt;
import com.medicare.Auth_Service.Services.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthConfig {

    private final AuthEntryPointJwt point;
//    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService;
    private final AuthenticationSuccessHandler oauth2SuccessHandler;


    @Bean
    public UserDetailsService userDetailsService(){
        return new CustomUserDetailsService();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Configuring exception handling, session management, and authorization rules
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(point))
                .authorizeHttpRequests(auth -> auth
//                                .requestMatchers("/auth/signUp", "/auth/signIn", "/auth/google-login","/auth/.well-known/**","/auth/validate").permitAll()
//                                .requestMatchers( "/auth/revokeUserToken").authenticated()
                                .anyRequest().permitAll()
                )
                .oauth2Login(o -> o
//                        .userInfoEndpoint(u -> u.userService(oAuth2UserService))
                        .successHandler(oauth2SuccessHandler)
                );
        // Adding custom authentication provider
        http.authenticationProvider(authenticationProvider());
        // Configuring CSRF and CORS
        http.csrf(AbstractHttpConfigurer::disable).cors(cors -> new CorsConfig());
        // Building and returning the configured security filter chain
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider=new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}