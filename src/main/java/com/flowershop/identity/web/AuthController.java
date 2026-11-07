package com.flowershop.identity.web;

import com.flowershop.common.api.ApiResponse;
import com.flowershop.identity.dto.*;
import com.flowershop.identity.security.ClientInfo;
import com.flowershop.identity.service.AuthService;
import com.flowershop.identity.service.RegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RegistrationService registrationService;

    /** Response chứa token: cấm mọi tầng cache (trình duyệt, proxy) lưu lại. */
    private static <T> ResponseEntity<ApiResponse<T>> noStore(T body) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(ApiResponse.success(body));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest req,
                                                            HttpServletRequest http) {
        return noStore(authService.login(req, ClientInfo.from(http)));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<TokenResponse>> refresh(@Valid @RequestBody RefreshTokenRequest req,
                                                              HttpServletRequest http) {
        return noStore(authService.refresh(req.refreshToken(), ClientInfo.from(http)));
    }

    @PostMapping("/logout")
    public ApiResponse<Void> logout(@Valid @RequestBody RefreshTokenRequest req, HttpServletRequest http) {
        authService.logout(req.refreshToken(), ClientInfo.from(http));
        return ApiResponse.success("Đã đăng xuất", null);
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<RegisterResponse>> register(@Valid @RequestBody RegisterRequest req,
                                                                  HttpServletRequest http) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(registrationService.register(req, ClientInfo.from(http))));
    }

    @GetMapping("/me")
    public ApiResponse<MeResponse> me() {
        return ApiResponse.success(authService.me());
    }

    @PostMapping("/change-password")
    public ApiResponse<Void> changePassword(@Valid @RequestBody ChangePasswordRequest req, HttpServletRequest http) {
        authService.changePassword(req, ClientInfo.from(http));
        return ApiResponse.success("Đã đổi mật khẩu, vui lòng đăng nhập lại", null);
    }
}
