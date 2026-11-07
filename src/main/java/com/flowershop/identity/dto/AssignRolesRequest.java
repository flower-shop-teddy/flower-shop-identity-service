package com.flowershop.identity.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.Set;

public record AssignRolesRequest(@NotEmpty @Size(max = 10) Set<@NotBlank String> roles) {
}
