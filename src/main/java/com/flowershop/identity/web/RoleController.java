package com.flowershop.identity.web;

import com.flowershop.common.api.ApiResponse;
import com.flowershop.identity.dto.RoleResponse;
import com.flowershop.identity.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService service;

    @GetMapping
    @PreAuthorize("hasAuthority('role:read')")
    public ApiResponse<List<RoleResponse>> list() {
        return ApiResponse.success(service.list());
    }
}
