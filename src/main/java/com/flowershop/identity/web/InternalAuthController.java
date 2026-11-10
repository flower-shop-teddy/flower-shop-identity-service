package com.flowershop.identity.web;

import com.flowershop.common.api.ApiResponse;
import com.flowershop.identity.dto.ServiceTokenRequest;
import com.flowershop.identity.dto.ServiceTokenResponse;
import com.flowershop.identity.security.ClientInfo;
import com.flowershop.identity.service.ServiceTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * API chỉ dành cho các service trong hệ thống.
 * Prefix /internal/** KHÔNG có route ở api-gateway: từ Internet gọi vào sẽ nhận 404.
 * Môi trường thật còn chặn thêm ở tầng mạng (chỉ mạng nội bộ của cluster mới tới được cổng 8083).
 */
@RestController
@RequestMapping("/internal/v1")
@RequiredArgsConstructor
public class InternalAuthController {

    private final ServiceTokenService serviceTokenService;

    @PostMapping("/service-token")
    public ResponseEntity<ApiResponse<ServiceTokenResponse>> serviceToken(@Valid @RequestBody ServiceTokenRequest req,
                                                                          HttpServletRequest http) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(ApiResponse.success(serviceTokenService.issue(req, ClientInfo.from(http))));
    }
}
