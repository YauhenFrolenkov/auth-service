package com.innowise.auth.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CustomAccessDeniedHandlerTest {

    private CustomAccessDeniedHandler handler;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        handler = new CustomAccessDeniedHandler();
        response = new MockHttpServletResponse();
    }

    @Test
    void shouldReturnForbidden() throws IOException, ServletException {
        HttpServletRequest request = new MockHttpServletRequest();
        AccessDeniedException ex = new AccessDeniedException("denied");

        handler.handle(request, response, ex);

        assertEquals(403, response.getStatus());
        assertEquals("application/json", response.getContentType());
    }
}
