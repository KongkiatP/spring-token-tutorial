package com.interview.token.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    public CustomUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // ปกติจะดึงจาก DB: userRepository.findByUsername(username)
        // ตัวอย่าง mock: มี user คนเดียวชื่อ "john" password "123456"
        if (!"john".equals(username)) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        return User.withUsername("john")
                .password(passwordEncoder.encode("123456"))
                .roles("USER")
                .build();
    }
}
