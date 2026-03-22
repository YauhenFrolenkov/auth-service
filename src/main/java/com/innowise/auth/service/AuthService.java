package com.innowise.auth.service;

import com.innowise.auth.dto.AuthRequestDto;
import com.innowise.auth.dto.AuthResponseDto;
import com.innowise.auth.dto.RegisterRequest;

public interface AuthService {

    AuthResponseDto login(AuthRequestDto request);
    AuthResponseDto refresh(String refreshToken);
    void register(RegisterRequest request);
    boolean validateToken(String token);
}
