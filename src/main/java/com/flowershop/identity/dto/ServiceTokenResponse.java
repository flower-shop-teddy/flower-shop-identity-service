package com.flowershop.identity.dto;

/** Service token KHÔNG có refresh token: hết hạn thì xin lại bằng client id + secret. */
public record ServiceTokenResponse(String tokenType, String accessToken, long expiresIn) {

    @Override
    public String toString() {
        return "ServiceTokenResponse[expiresIn=" + expiresIn + "]";
    }
}
