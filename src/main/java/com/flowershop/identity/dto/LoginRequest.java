package com.flowershop.identity.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * @param loginId username (nhân viên) hoặc số điện thoại (khách)
 */
public record LoginRequest(
        @NotBlank @Size(max = 50) String loginId,
        @NotBlank @Size(max = 128) String password
) {
    /** Không bao giờ in mật khẩu ra log, kể cả khi ai đó lỡ log cả object request. */
    @Override
    public String toString() {
        return "LoginRequest[loginId=" + loginId + ", password=***]";
    }
}
