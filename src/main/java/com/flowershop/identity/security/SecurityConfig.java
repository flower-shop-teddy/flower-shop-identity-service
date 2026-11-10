package com.flowershop.identity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flowershop.common.security.ApiSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Luật truy cập của identity-service.
 * Lớp 1 (URL): API nào public, còn lại phải có token hợp lệ.
 * Lớp 2 (method): @PreAuthorize trên từng API quản trị, kiểm tra permission cụ thể.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ObjectMapper objectMapper) throws Exception {
        ApiSecurity.configure(http, objectMapper);
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST,
                        "/api/v1/auth/login", "/api/v1/auth/refresh",
                        "/api/v1/auth/logout", "/api/v1/auth/register").permitAll()
                // Service tự xác thực bằng client id + secret trong body (gateway không route /internal/**)
                .requestMatchers(HttpMethod.POST, "/internal/v1/service-token").permitAll()
                .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json").permitAll()
                .requestMatchers("/actuator/health/**", "/actuator/info").permitAll()
                // Swagger chỉ bật ở profile local (springdoc.*.enabled), tắt thì các path này trả 404
                .requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}
