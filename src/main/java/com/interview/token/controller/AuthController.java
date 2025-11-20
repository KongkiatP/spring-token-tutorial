package com.interview.token.controller;

import com.interview.token.security.JwtTokenProvider;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtTokenProvider tokenProvider;

    public AuthController(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /**
     * Endpoint ง่าย ๆ สำหรับออก token ไว้ใช้ทดสอบ
     * ตัวอย่าง: POST /auth/token?username=john
     */
    @PostMapping("/token")
    public Map<String, String> generateToken(@RequestParam String username) {
        String token = tokenProvider.generateToken(username);
        return Map.of("token", token);
    }
}
