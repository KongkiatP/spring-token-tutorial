package com.interview.token.controller;

import com.interview.token.security.JwtTokenProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;

    public LoginController(AuthenticationManager authenticationManager,
                           JwtTokenProvider tokenProvider) {
        this.authenticationManager = authenticationManager;
        this.tokenProvider = tokenProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            // 1) สร้าง Authentication object จาก username/password ที่ client ส่งมา
            Authentication authRequest = new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
            );

            // 2) ส่งให้ AuthenticationManager ตรวจ
            Authentication authResult = authenticationManager.authenticate(authRequest);

            // 3) ถ้าสำเร็จ → สร้าง JWT token จาก username (หรือ principal)
            String username = authResult.getName();
            String token = tokenProvider.generateToken(username);

            return ResponseEntity.ok(Map.of(
                    "username", username,
                    "token", token
            ));
        } catch (BadCredentialsException ex) {
            // username/password ผิด
            return ResponseEntity.status(401).body(Map.of(
                    "error", "invalid_credentials",
                    "message", "Username or password is incorrect"
            ));
        }
    }
}
