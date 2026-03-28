package com.innowise.auth.controller;

import com.innowise.auth.dto.*;
import com.innowise.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for authentication endpoints.
 * Handles user registration, login, token refresh, and token validation requests.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Registers a new user.
     *
     * @param request the registration request
     * @return HTTP 200 OK if registration is successful
     */
    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.ok().build();
    }

    /**
     * Logs in a user and returns JWT tokens.
     *
     * @param request the login request
     * @return JWT access and refresh tokens in AuthResponseDto
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@Valid @RequestBody AuthRequestDto request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * Refreshes JWT tokens using a refresh token.
     *
     * @param request the refresh token request
     * @return new JWT access and refresh tokens in AuthResponseDto
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request.getRefreshToken()));
    }

    /**
     * Validates the provided JWT token.
     *
     * @param request the token validation request
     * @return true if token is valid, false otherwise
     */
    @PostMapping("/validate")
    public ResponseEntity<Boolean> validate(@Valid @RequestBody TokenValidationRequest request) {
        return ResponseEntity.ok(authService.validateToken(request.getToken()));
    }
}
