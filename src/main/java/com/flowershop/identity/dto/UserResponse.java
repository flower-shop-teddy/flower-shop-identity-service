package com.flowershop.identity.dto;

import com.flowershop.common.security.UserType;
import com.flowershop.identity.domain.UserStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** SĐT trả về đã che: màn hình quản trị không cần thấy đầy đủ. */
public record UserResponse(
        UUID publicId,
        UserType userType,
        String username,
        String phoneMasked,
        Long customerId,
        UserStatus status,
        boolean locked,
        Instant lockedUntil,
        boolean passwordChangeRequired,
        List<String> roles,
        Instant lastLoginAt,
        Instant createdAt,
        String createdBy
) {
}
