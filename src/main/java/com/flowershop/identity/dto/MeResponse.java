package com.flowershop.identity.dto;

import com.flowershop.common.security.UserType;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record MeResponse(
        UUID publicId,
        UserType userType,
        String username,
        String phone,
        Long customerId,
        List<String> roles,
        List<String> permissions,
        boolean passwordChangeRequired,
        Instant lastLoginAt
) {
}
