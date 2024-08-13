package com.rezguiyassine.springsecurityProject.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor

public class AuthTokenFilter extends OncePerRequestFilter {
    //jwtService
    private final JwtService jwtService;

    @Override
    protected void doFilterInternal
            (@NonNull HttpServletRequest request,
             @NonNull HttpServletResponse response,
             @NonNull FilterChain filterChain
            ) throws ServletException, IOException {
        // Get the Authorization header from the request
        final String authorizationHeader = request.getHeader("Authorization");
        final String jwt;
        final  String userEmail;
        // Check if the Authorization header is not null and starts with "Bearer "
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer")){
            // If the Authorization header is not valid, we move to the next filter
            filterChain.doFilter(request, response);
            return;
        } else {
            // If the Authorization header is valid, we extract the JWT token
            jwt = authorizationHeader.substring(7);
            // We extract the user email from the JWT token
            userEmail = jwtService.extractUsernamel(jwt);// extractEmail(jwt);
        }

    }
}
