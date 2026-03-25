package com.innowise.auth.service.impl;

import com.innowise.auth.dto.AuthRequestDto;
import com.innowise.auth.dto.AuthResponseDto;
import com.innowise.auth.dto.RegisterRequest;
import com.innowise.auth.entity.Role;
import com.innowise.auth.entity.User;
import com.innowise.auth.repository.RoleRepository;
import com.innowise.auth.repository.UserRepository;
import com.innowise.auth.security.JwtProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtProvider jwtProvider;

    @InjectMocks
    private AuthServiceImpl authService;

    @Test
    void shouldRegisterUser() {
        RegisterRequest request = new RegisterRequest("test", "1234");

        Role role = new Role(1L, Role.RoleName.USER);

        when(userRepository.existsByUsername("test")).thenReturn(false);
        when(roleRepository.findByName(Role.RoleName.USER)).thenReturn(Optional.of(role));
        when(passwordEncoder.encode("1234")).thenReturn("encoded");

        authService.register(request);

        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void shouldLoginSuccessfully() {
        AuthRequestDto request = new AuthRequestDto("test", "1234");

        Role role = new Role(1L, Role.RoleName.USER);
        User user = User.builder()
                .id(1L)
                .username("test")
                .password("encoded")
                .roles(Set.of(role))
                .build();

        when(userRepository.findByUsername("test")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("1234", "encoded")).thenReturn(true);
        when(jwtProvider.generateAccessToken(1L, "USER")).thenReturn("access");
        when(jwtProvider.generateRefreshToken(1L)).thenReturn("refresh");

        AuthResponseDto response = authService.login(request);

        assertNotNull(response);
        assertEquals("access", response.getAccessToken());
        assertEquals("refresh", response.getRefreshToken());
    }

    @Test
    void shouldThrowExceptionIfUserNotFound() {
        AuthRequestDto request = new AuthRequestDto("test", "1234");

        when(userRepository.findByUsername("test")).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> authService.login(request));
    }

    @Test
    void shouldThrowExceptionIfPasswordInvalid() {
        AuthRequestDto request = new AuthRequestDto("test", "1234");

        User user = User.builder()
                .id(1L)
                .username("test")
                .password("encoded")
                .roles(Set.of(new Role(1L, Role.RoleName.USER)))
                .build();

        when(userRepository.findByUsername("test")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("1234", "encoded")).thenReturn(false);

        assertThrows(RuntimeException.class, () -> authService.login(request));
    }

    @Test
    void shouldValidateToken() {
        String token = "validToken";

        when(jwtProvider.validateToken(token)).thenReturn(true);

        boolean result = authService.validateToken(token);

        assertTrue(result);
    }

    @Test
    void shouldThrowExceptionIfUserAlreadyExists() {
        RegisterRequest request = new RegisterRequest("test", "1234");

        when(userRepository.existsByUsername("test")).thenReturn(true);

        assertThrows(RuntimeException.class, () -> authService.register(request));

        verify(userRepository, never()).save(any());
    }

    @Test
    void shouldThrowExceptionIfRoleNotFound() {
        RegisterRequest request = new RegisterRequest("test", "1234");

        when(userRepository.existsByUsername("test")).thenReturn(false);
        when(roleRepository.findByName(Role.RoleName.USER)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> authService.register(request));
    }

    @Test
    void shouldReturnFalseIfTokenInvalid() {
        String token = "invalidToken";

        when(jwtProvider.validateToken(token)).thenReturn(false);

        boolean result = authService.validateToken(token);

        assertFalse(result);
    }

    @Test
    void shouldThrowExceptionIfRefreshTokenInvalid() {
        String refreshToken = "invalid";

        when(jwtProvider.validateToken(refreshToken)).thenReturn(false);

        assertThrows(RuntimeException.class, () -> authService.refresh(refreshToken));
    }
}
