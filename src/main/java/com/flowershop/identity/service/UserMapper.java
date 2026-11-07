package com.flowershop.identity.service;

import com.flowershop.common.util.DataMasking;
import com.flowershop.identity.domain.Role;
import com.flowershop.identity.domain.UserAccount;
import com.flowershop.identity.dto.MeResponse;
import com.flowershop.identity.dto.RoleResponse;
import com.flowershop.identity.dto.UserResponse;

import java.time.Instant;

final class UserMapper {

    private UserMapper() {
    }

    static UserResponse toResponse(UserAccount u, Instant now) {
        return new UserResponse(u.getPublicId(), u.getUserType(), u.getUsername(),
                DataMasking.maskTail(u.getPhone(), 3), u.getCustomerId(), u.getStatus(),
                u.isLocked(now), u.isLocked(now) ? u.getLockedUntil() : null, u.isMustChangePassword(),
                u.roleCodes(), u.getLastLoginAt(), u.getCreatedAt(), u.getCreatedBy());
    }

    /** Thông tin của CHÍNH MÌNH thì được thấy SĐT đầy đủ. */
    static MeResponse toMe(UserAccount u) {
        return new MeResponse(u.getPublicId(), u.getUserType(), u.getUsername(), u.getPhone(), u.getCustomerId(),
                u.roleCodes(), u.isMustChangePassword() ? java.util.List.of() : u.permissionCodes(),
                u.isMustChangePassword(), u.getLastLoginAt());
    }

    static RoleResponse toResponse(Role r) {
        return new RoleResponse(r.getCode(), r.getName(), r.isSystem(),
                r.getPermissions().stream().map(p -> p.getCode()).sorted().toList());
    }
}
