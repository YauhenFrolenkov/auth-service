package com.innowise.auth.controller;

import com.innowise.auth.security.JwtProvider;
import com.innowise.auth.service.AuthService;
import com.innowise.auth.dto.AuthRequestDto;
import com.innowise.auth.dto.AuthResponseDto;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class AuthControllerIT {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtProvider jwtProvider;

    @Test
    @DisplayName("Login returns tokens")
    void login_shouldReturnTokens() throws Exception {
        AuthResponseDto responseDto = new AuthResponseDto("access-token", "refresh-token");

        when(authService.login(any(AuthRequestDto.class))).thenReturn(responseDto);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"test\",\"password\":\"1234\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"));
    }

    @Test
    @DisplayName("Register creates new user")
    void register_shouldRegisterUser() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"test\",\"password\":\"1234\"}"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Refresh returns new access token")
    void refresh_shouldReturnNewAccessToken() throws Exception {
        AuthResponseDto responseDto = new AuthResponseDto("new-access-token", "refresh-token");
        when(authService.refresh("refresh-token")).thenReturn(responseDto);

        mockMvc.perform(post("/auth/refresh")
                        .param("refreshToken", "refresh-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"));
    }

    @Test
    @DisplayName("Validate returns true")
    void validate_shouldReturnTrue() throws Exception {
        when(authService.validateToken("valid-token")).thenReturn(true);

        mockMvc.perform(get("/auth/validate")
                        .param("token", "valid-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value(true));
    }
}


