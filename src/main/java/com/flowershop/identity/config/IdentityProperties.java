package com.flowershop.identity.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.Map;

/** Cấu hình identity.* trong application.yml. @Validated: sai cấu hình thì service không khởi động (fail fast). */
@Validated
@ConfigurationProperties(prefix = "identity")
public record IdentityProperties(
        @Valid @NotNull Jwt jwt,
        @Valid @NotNull RefreshToken refreshToken,
        @Valid @NotNull Login login,
        @Valid @NotNull Password password,
        @Valid @NotNull BootstrapAdmin bootstrapAdmin,
        @Valid @NotNull CustomerService customerService
) {
    public record Jwt(
            @NotBlank String issuer,
            @NotBlank String audience,
            @NotNull Duration accessTokenTtl,
            @NotNull Duration serviceTokenTtl,
            String keyId,
            String privateKey,
            boolean generateDevKey,
            Map<String, String> retiredPublicKeys
    ) {
    }

    public record RefreshToken(@NotNull Duration ttl) {
    }

    public record Login(@Min(1) int maxFailedAttempts, @NotNull Duration lockDuration) {
    }

    public record Password(@Min(4) @Max(16) int bcryptStrength) {
    }

    public record BootstrapAdmin(String username, String password) {
    }

    public record CustomerService(@NotBlank String baseUrl, @NotNull Duration connectTimeout,
                                  @NotNull Duration readTimeout) {
    }
}
