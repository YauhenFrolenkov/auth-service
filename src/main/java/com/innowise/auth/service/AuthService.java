package com.innowise.auth.service;

import com.innowise.auth.dto.AuthRequestDto;
import com.innowise.auth.dto.AuthResponseDto;
import com.innowise.auth.dto.RegisterRequest;

/**
 * Service interface for authentication-related operations.
 * Provides methods for user registration, login, token refresh, and token validation.
 */
public interface AuthService {

    /**
     * Authenticates a user with the given credentials and returns JWT access and refresh tokens.
     *
     * @param request the login request containing username and password
     * @return an AuthResponseDto containing access and refresh tokens
     */
    AuthResponseDto login(AuthRequestDto request);

    /**
     * Refreshes the JWT tokens using the provided refresh token.
     *
     * @param refreshToken the refresh token
     * @return a new AuthResponseDto with new access and refresh tokens
     */
    AuthResponseDto refresh(String refreshToken);

    /**
     * Registers a new user with the provided credentials.
     *
     * @param request the registration request containing username and password
     */
    void register(RegisterRequest request);

    /**
     * Validates the provided JWT token.
     *
     * @param token the JWT token to validate
     * @return true if the token is valid, false otherwise
     */
    boolean validateToken(String token);
}
