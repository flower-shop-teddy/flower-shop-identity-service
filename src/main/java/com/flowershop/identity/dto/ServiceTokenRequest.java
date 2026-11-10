package com.flowershop.identity.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** client_credentials: service tự xác thực bằng client id + secret. */
public record ServiceTokenRequest(
        @NotBlank @Pattern(regexp = "^[a-z][a-z0-9-]{2,49}$") String clientId,
        // bcrypt chỉ dùng 72 byte đầu: secret dài hơn thì phần thừa không có tác dụng
        @NotBlank @Size(max = 72) String clientSecret
) {
    /** Không bao giờ in secret ra log. */
    @Override
    public String toString() {
        return "ServiceTokenRequest[clientId=" + clientId + "]";
    }
}
