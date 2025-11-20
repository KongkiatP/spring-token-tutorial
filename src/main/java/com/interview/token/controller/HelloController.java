package com.interview.token.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class HelloController {

    @GetMapping("/hello")
    public Map<String, String> hello(Authentication authentication) {
        String username = authentication != null ? authentication.getName() : "anonymous";
        return Map.of("message", "Hello, " + username);
    }
}
