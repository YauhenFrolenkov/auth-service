package com.innowise.auth.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleUserHasNoRoles() {
        UserHasNoRolesException ex = new UserHasNoRolesException("No roles");

        ResponseEntity<Map<String, Object>> response =
                handler.handleUserHasNoRoles(ex);

        assertEquals(401, response.getStatusCode().value());
        assertEquals("No roles", response.getBody().get("message"));
    }

    @Test
    void handleUserAlreadyExists() {
        UserAlreadyExistsException ex = new UserAlreadyExistsException("exists");

        ResponseEntity<Map<String, Object>> response =
                handler.handleUserExists(ex);

        assertEquals(409, response.getStatusCode().value());
    }

    @Test
    void handleInvalidCredentials() {
        InvalidCredentialsException ex = new InvalidCredentialsException("bad");

        ResponseEntity<Map<String, Object>> response =
                handler.handleInvalidCredentials(ex);

        assertEquals(401, response.getStatusCode().value());
    }
}
