package com.flowershop.identity.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshTokenRequest(@NotBlank @Size(max = 100) String refreshToken) {
    @Override
    public String toString() {
        return "RefreshTokenRequest[***]";
    }
}
