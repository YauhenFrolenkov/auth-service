package com.innowise.auth.controller;

import com.innowise.auth.dto.AuthRequestDto;
import com.innowise.auth.dto.AuthResponseDto;
import com.innowise.auth.dto.RegisterRequest;
import com.innowise.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@RequestBody AuthRequestDto request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refresh(@RequestParam String refreshToken) {
        return ResponseEntity.ok(authService.refresh(refreshToken));
    }

    @GetMapping("/validate")
    public ResponseEntity<Boolean> validate(@RequestParam String token) {
        return ResponseEntity.ok(authService.validateToken(token));
    }

}
