package com.flowershop.identity.dto;

import jakarta.validation.constraints.*;

import java.time.LocalDate;

/** Khách tự đăng ký. Phần hồ sơ (họ tên, email, ngày sinh) được chuyển sang customer-service. */
public record RegisterRequest(
        @NotBlank
        @Pattern(regexp = "^0\\d{9}$", message = "Số điện thoại gồm 10 chữ số, bắt đầu bằng 0")
        String phone,

        @NotBlank @Size(max = 128)
        String password,

        @NotBlank @Size(max = 150)
        String fullName,

        @Email @Size(max = 254)
        String email,

        @Past(message = "Ngày sinh phải ở quá khứ")
        LocalDate dateOfBirth
) {
    @Override
    public String toString() {
        return "RegisterRequest[***]";
    }
}
