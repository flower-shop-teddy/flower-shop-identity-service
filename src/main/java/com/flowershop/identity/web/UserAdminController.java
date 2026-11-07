package com.flowershop.identity.web;

import com.flowershop.common.api.ApiResponse;
import com.flowershop.common.api.PageResponse;
import com.flowershop.common.security.UserType;
import com.flowershop.identity.dto.AssignRolesRequest;
import com.flowershop.identity.dto.CreateStaffRequest;
import com.flowershop.identity.dto.TemporaryPasswordResponse;
import com.flowershop.identity.dto.UserResponse;
import com.flowershop.identity.security.ClientInfo;
import com.flowershop.identity.service.UserAdminService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/** Quản trị tài khoản. Mỗi API khai báo đúng permission cần có. */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserAdminController {

    private final UserAdminService service;

    @GetMapping
    @PreAuthorize("hasAuthority('user:read')")
    public ApiResponse<PageResponse<UserResponse>> list(@RequestParam(required = false) UserType type,
                                                        @RequestParam(defaultValue = "0") int page,
                                                        @RequestParam(defaultValue = "20") int size) {
        return ApiResponse.success(service.list(type, page, size));
    }

    @GetMapping("/{publicId}")
    @PreAuthorize("hasAuthority('user:read')")
    public ApiResponse<UserResponse> get(@PathVariable UUID publicId) {
        return ApiResponse.success(service.get(publicId));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('user:write')")
    public ResponseEntity<ApiResponse<TemporaryPasswordResponse>> createStaff(
            @Valid @RequestBody CreateStaffRequest req, HttpServletRequest http) {
        return ResponseEntity.status(HttpStatus.CREATED).cacheControl(CacheControl.noStore())
                .body(ApiResponse.success(service.createStaff(req, ClientInfo.from(http))));
    }

    @PutMapping("/{publicId}/roles")
    @PreAuthorize("hasAuthority('role:assign')")
    public ApiResponse<UserResponse> assignRoles(@PathVariable UUID publicId,
                                                 @Valid @RequestBody AssignRolesRequest req,
                                                 HttpServletRequest http) {
        return ApiResponse.success(service.assignRoles(publicId, req.roles(), ClientInfo.from(http)));
    }

    @PostMapping("/{publicId}/disable")
    @PreAuthorize("hasAuthority('user:write')")
    public ApiResponse<UserResponse> disable(@PathVariable UUID publicId, HttpServletRequest http) {
        return ApiResponse.success(service.disable(publicId, ClientInfo.from(http)));
    }

    @PostMapping("/{publicId}/enable")
    @PreAuthorize("hasAuthority('user:write')")
    public ApiResponse<UserResponse> enable(@PathVariable UUID publicId, HttpServletRequest http) {
        return ApiResponse.success(service.enable(publicId, ClientInfo.from(http)));
    }

    @PostMapping("/{publicId}/unlock")
    @PreAuthorize("hasAuthority('user:write')")
    public ApiResponse<UserResponse> unlock(@PathVariable UUID publicId, HttpServletRequest http) {
        return ApiResponse.success(service.unlock(publicId, ClientInfo.from(http)));
    }

    @PostMapping("/{publicId}/reset-password")
    @PreAuthorize("hasAuthority('user:write')")
    public ResponseEntity<ApiResponse<TemporaryPasswordResponse>> resetPassword(@PathVariable UUID publicId,
                                                                                HttpServletRequest http) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(ApiResponse.success(service.resetPassword(publicId, ClientInfo.from(http))));
    }
}
