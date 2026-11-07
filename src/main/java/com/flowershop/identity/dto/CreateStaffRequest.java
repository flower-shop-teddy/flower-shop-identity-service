package com.flowershop.identity.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Set;

public record CreateStaffRequest(
        @NotBlank
        @Pattern(regexp = "^[a-zA-Z][a-zA-Z0-9._]{2,49}$",
                message = "Username 3-50 ký tự, bắt đầu bằng chữ cái, chỉ gồm chữ, số, dấu chấm, gạch dưới")
        String username,

        @NotEmpty @Size(max = 10)
        Set<@NotBlank String> roles
) {
}
