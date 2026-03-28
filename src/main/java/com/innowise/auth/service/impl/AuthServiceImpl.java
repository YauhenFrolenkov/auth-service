package com.innowise.auth.service.impl;

import com.innowise.auth.dto.AuthRequestDto;
import com.innowise.auth.dto.AuthResponseDto;
import com.innowise.auth.dto.RegisterRequest;
import com.innowise.auth.entity.Role;
import com.innowise.auth.entity.User;
import com.innowise.auth.exception.InvalidCredentialsException;
import com.innowise.auth.exception.ResourceNotFoundException;
import com.innowise.auth.exception.UserAlreadyExistsException;
import com.innowise.auth.exception.UserHasNoRolesException;
import com.innowise.auth.repository.RoleRepository;
import com.innowise.auth.repository.UserRepository;
import com.innowise.auth.security.JwtProvider;
import com.innowise.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    @Override
    public void register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("User already exists");
        }

        Role role = roleRepository.findByName(Role.RoleName.USER)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(role))
                .build();

        userRepository.save(user);
    }

    @Override
    public AuthResponseDto login(AuthRequestDto request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid username or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new InvalidCredentialsException("Invalid username or password");
        }

        Set<Role> roles = user.getRoles();
        if (roles.isEmpty()) {
            throw new UserHasNoRolesException("User has no roles assigned");
        }

        String role = roles.iterator().next().getName().name();

        String accessToken = jwtProvider.generateAccessToken(user.getId(), role);
        String refreshToken = jwtProvider.generateRefreshToken(user.getId());

        return new AuthResponseDto(accessToken, refreshToken);
    }

    @Override
    public AuthResponseDto refresh(String refreshToken) {
        if (!jwtProvider.validateToken(refreshToken) || !jwtProvider.isRefreshToken(refreshToken)) {
            throw new InvalidCredentialsException("Invalid refresh token");
        }

        Long userId = jwtProvider.getUserIdFromToken(refreshToken);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Set<Role> roles = user.getRoles();
        if (roles.isEmpty()) {
            throw new UserHasNoRolesException("User has no roles assigned");
        }

        String role = roles.iterator().next().getName().name();

        String newAccessToken = jwtProvider.generateAccessToken(user.getId(), role);
        String newRefreshToken = jwtProvider.generateRefreshToken(user.getId());

        return new AuthResponseDto(newAccessToken, newRefreshToken);
    }

    @Override
    public boolean validateToken(String token) {
        return jwtProvider.validateToken(token);
    }

}
