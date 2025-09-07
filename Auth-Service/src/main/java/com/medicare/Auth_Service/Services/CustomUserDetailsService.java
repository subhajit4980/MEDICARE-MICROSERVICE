package com.medicare.Auth_Service.Services;

import com.medicare.Auth_Service.Model.User;
import com.medicare.Auth_Service.Repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

@Component
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        String norm = email.trim().toLowerCase(Locale.ROOT);
        User user = userRepository.findByEmail(norm)
                .orElseThrow(() -> new UsernameNotFoundException("user not found with email: " + email));
        return new CustomUserDetails(user);
    }
}
