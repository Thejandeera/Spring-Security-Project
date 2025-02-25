package com.thejan.security_tutorial.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// Marks this as a configuration class for Spring
@Configuration
// Enables Spring Security's web security features
@EnableWebSecurity
// Lombok annotation that creates a constructor with required fields
@RequiredArgsConstructor
public class SecurityConfiguration {
    // JWT authentication filter to process JWT tokens in requests
    private final JwtAuthenticationFilter jwtAuthFilter;
    // Provider that will authenticate users
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF protection since we're using stateless JWT authentication
                // and not using cookies for session management
                .csrf(csrf -> csrf.disable())

                // Configure authorization rules for HTTP requests using the new lambda style
                .authorizeHttpRequests(auth -> auth
                        // Define which endpoints are publicly accessible without authentication
                        // Here we're allowing all paths matching "/api/v1/auth/**" (like login, register)
                        .requestMatchers("/api/v1/auth/**")
                        // The permitAll() means no authentication required for the above paths
                        .permitAll()
                        // This applies to all other requests not matched above
                        .anyRequest()
                        // All other endpoints require authentication
                        .authenticated())

                // Configure session management
                .sessionManagement(session -> session
                        // Set to STATELESS because we're using JWTs and not storing session on the server
                        // Each request will be authenticated based on the JWT token
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Register our custom authentication provider
                // This is what will validate user credentials during authentication
                .authenticationProvider(authenticationProvider)

                // Add our JWT filter before the standard UsernamePasswordAuthenticationFilter
                // This ensures JWT tokens are processed before attempting username/password authentication
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        // Build and return the configured security filter chain
        return http.build();
    }
}