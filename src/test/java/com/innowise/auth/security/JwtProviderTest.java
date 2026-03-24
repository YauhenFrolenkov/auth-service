package com.innowise.auth.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtProviderTest {

    private JwtProvider jwtProvider;

    @BeforeEach
    void setUp() {
        jwtProvider = new JwtProvider();
    }

    @Test
    void shouldGenerateAndValidateAccessToken() {
        Long userId = 1L;
        String role = "USER";

        String token = jwtProvider.generateAccessToken(userId, role);

        assertNotNull(token);
        assertTrue(jwtProvider.validateToken(token));
    }

    @Test
    void shouldExtractUserIdFromToken() {
        Long userId = 2L;

        String token = jwtProvider.generateAccessToken(userId, "USER");

        Long extractedId = jwtProvider.getUserIdFromToken(token);

        assertEquals(userId, extractedId);
    }

    @Test
    void shouldExtractRoleFromToken() {
        String role = "ADMIN";

        String token = jwtProvider.generateAccessToken(1L, role);

        String extractedRole = jwtProvider.getRoleFromToken(token);

        assertEquals(role, extractedRole);
    }

    @Test
    void shouldGenerateRefreshToken() {
        String refreshToken = jwtProvider.generateRefreshToken(1L);

        assertNotNull(refreshToken);
        assertTrue(jwtProvider.validateToken(refreshToken));
    }

    @Test
    void shouldReturnFalseForInvalidToken() {
        String invalidToken = "invalid.token.value";

        assertFalse(jwtProvider.validateToken(invalidToken));
    }

    @Test
    void shouldContainCorrectUserIdAndRole() {
        Long userId = 99L;
        String role = "ADMIN";

        String token = jwtProvider.generateAccessToken(userId, role);

        assertEquals(userId, jwtProvider.getUserIdFromToken(token));
        assertEquals(role, jwtProvider.getRoleFromToken(token));
    }

    @Test
    void refreshTokenShouldContainOnlyUserId() {
        Long userId = 5L;

        String token = jwtProvider.generateRefreshToken(userId);

        assertEquals(userId, jwtProvider.getUserIdFromToken(token));

        assertNull(jwtProvider.getRoleFromToken(token));
    }
}
