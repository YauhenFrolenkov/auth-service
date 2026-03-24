package com.innowise.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.auth.dto.AuthRequestDto;
import com.innowise.auth.dto.AuthResponseDto;
import com.innowise.auth.dto.RegisterRequest;
import com.innowise.auth.security.JwtProvider;
import com.innowise.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;

import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtProvider jwtProvider;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void shouldRegisterUser() throws Exception {
        RegisterRequest request = new RegisterRequest("test", "1234");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldLoginUser() throws Exception {
        AuthRequestDto request = new AuthRequestDto("test", "1234");

        AuthResponseDto response = new AuthResponseDto("access", "refresh");

        when(authService.login(request)).thenReturn(response);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access"))
                .andExpect(jsonPath("$.refreshToken").value("refresh"));
    }

    @Test
    void refresh_shouldReturnNewAccessToken() throws Exception {
        AuthResponseDto response = new AuthResponseDto("newAccessToken", "newRefreshToken");

        when(authService.refresh(anyString())).thenReturn(response);

        mockMvc.perform(post("/auth/refresh")
                        .param("refreshToken", "testRefreshToken"))
                .andExpect(status().isOk());
    }

    @Test
    void validate_shouldReturnTrue() throws Exception {
        when(authService.validateToken(anyString())).thenReturn(true);

        mockMvc.perform(get("/auth/validate")
                        .param("token", "testToken"))
                .andExpect(status().isOk());
    }

    @Test
    void validate_shouldReturnFalse() throws Exception {
        when(authService.validateToken(anyString())).thenReturn(false);

        mockMvc.perform(get("/auth/validate")
                        .param("token", "invalidToken"))
                .andExpect(status().isOk());
    }


}

