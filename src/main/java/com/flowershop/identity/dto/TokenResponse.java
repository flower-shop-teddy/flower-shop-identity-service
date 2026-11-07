package com.flowershop.identity.dto;

/**
 * Chuẩn đặt tên gần giống OAuth2 token response (RFC 6749), nhưng dùng camelCase cho đồng bộ với API khác.
 * Web app thật nên để refresh token trong cookie HttpOnly + Secure + SameSite thay vì body.
 */
public record TokenResponse(
        String tokenType,
        String accessToken,
        long expiresIn,
        String refreshToken,
        long refreshExpiresIn,
        boolean passwordChangeRequired
) {
    @Override
    public String toString() {
        return "TokenResponse[expiresIn=" + expiresIn + ", passwordChangeRequired=" + passwordChangeRequired + "]";
    }
}
