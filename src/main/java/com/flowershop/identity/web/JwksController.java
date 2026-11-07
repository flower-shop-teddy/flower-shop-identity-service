package com.flowershop.identity.web;

import com.flowershop.identity.security.JwtKeyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

/**
 * JWKS (JSON Web Key Set, RFC 7517): danh sách PUBLIC key để service khác kiểm tra chữ ký JWT.
 * Đường dẫn /.well-known/jwks.json là quy ước chung, thư viện nào cũng hiểu.
 * Không bọc trong ApiResponse vì đây là định dạng chuẩn mà thư viện bên ngoài đọc trực tiếp.
 */
@RestController
@RequiredArgsConstructor
public class JwksController {

    private final JwtKeyService keys;

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(keys.publicJwkSet().toJSONObject(true));   // true = chỉ public key
    }
}
