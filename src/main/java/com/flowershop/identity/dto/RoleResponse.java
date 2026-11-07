package com.flowershop.identity.dto;

import java.util.List;

public record RoleResponse(String code, String name, boolean system, List<String> permissions) {
}
