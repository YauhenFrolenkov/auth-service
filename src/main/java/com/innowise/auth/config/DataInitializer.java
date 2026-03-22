package com.innowise.auth.config;

import com.innowise.auth.entity.Role;
import com.innowise.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@RequiredArgsConstructor
public class DataInitializer {

    private final RoleRepository roleRepository;

    @Bean
    public CommandLineRunner initRoles() {
        return args -> {
            if (roleRepository.findByName(Role.RoleName.ADMIN).isEmpty()) {
                roleRepository.save(
                        Role.builder().name(Role.RoleName.ADMIN).build()
                );
            }

            if (roleRepository.findByName(Role.RoleName.USER).isEmpty()) {
                roleRepository.save(
                        Role.builder().name(Role.RoleName.USER).build()
                );
            }
        };
    }
}
