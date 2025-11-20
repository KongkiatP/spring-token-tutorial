package com.interview.token.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;
    private final CustomUserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtTokenProvider tokenProvider,
                                    CustomUserDetailsService userDetailsService) {
        this.tokenProvider = tokenProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            // ไม่มี token ปล่อยให้ไปถึง AuthenticationEntryPoint
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);

        try {
            tokenProvider.validateToken(token);
            /* String username = tokenProvider.getUsernameFromToken(token);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, List.of());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); */

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,               // principal = UserDetails
                            null,                      // credentials = null (ไม่เก็บ password)
                            userDetails.getAuthorities() // สิทธิ์/role จาก DB
                    );
            authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException ex) {
            // token หมดอายุ
            request.setAttribute("auth_error", "token_expired");
            SecurityContextHolder.clearContext();
            filterChain.doFilter(request, response);
        } catch (JwtException ex) {
            // token ไม่ถูกต้อง
            request.setAttribute("auth_error", "invalid_token");
            SecurityContextHolder.clearContext();
            filterChain.doFilter(request, response);
        }
    }
}
