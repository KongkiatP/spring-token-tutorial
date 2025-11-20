package com.interview.token.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        String authError = (String) request.getAttribute("auth_error");
        String error;
        String message;

        if ("token_expired".equals(authError)) {
            error = "token_expired";
            message = "Access token has expired";
        } else if ("invalid_token".equals(authError)) {
            error = "invalid_token";
            message = "Invalid access token";
        } else {
            error = "unauthorized";
            message = "Missing or invalid authentication";
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");

        Map<String, String> body = new HashMap<>();
        body.put("error", error);
        body.put("message", message);

        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
