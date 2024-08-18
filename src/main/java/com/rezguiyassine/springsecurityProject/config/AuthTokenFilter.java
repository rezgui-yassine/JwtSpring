package com.rezguiyassine.springsecurityProject.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor

public class AuthTokenFilter extends OncePerRequestFilter {
    //jwtService
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

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
            userEmail = jwtService.extractUsername(jwt);// extractEmail(jwt);
            // If the user email is not null and the user is not authenticated
            if (userEmail!= null && SecurityContextHolder.getContext().getAuthentication() == null){
               // We load the user details from the user email
                UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
                // If the JWT token is valid, we set the user details in the SecurityContext
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    // We create an authentication token
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    // We set the details of the authentication token
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // We set the authentication token in the SecurityContext
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
            filterChain.doFilter(request, response);
        }
        

    }
}
