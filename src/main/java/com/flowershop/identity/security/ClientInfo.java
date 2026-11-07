package com.flowershop.identity.security;

import jakarta.servlet.http.HttpServletRequest;

import java.util.regex.Pattern;

/**
 * IP và trình duyệt của người dùng, ghi vào nhật ký đăng nhập và refresh token.
 *
 * Đứng sau gateway nên request.getRemoteAddr() là IP của GATEWAY. IP thật nằm trong X-Forwarded-For,
 * gateway NỐI THÊM IP nó nhìn thấy vào CUỐI header. Phần đầu header do client tự gửi, giả mạo được,
 * nên chỉ tin phần tử CUỐI CÙNG (do gateway của mình thêm vào).
 */
public record ClientInfo(String ip, String userAgent) {

    private static final Pattern SAFE_IP = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");
    private static final int MAX_USER_AGENT = 255;

    public static final ClientInfo UNKNOWN = new ClientInfo(null, null);

    public static ClientInfo from(HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            String[] parts = forwarded.split(",");
            ip = parts[parts.length - 1].strip();
        }
        if (ip != null && !SAFE_IP.matcher(ip).matches()) {
            ip = null;   // không ghi chuỗi lạ vào log/DB
        }
        String ua = request.getHeader("User-Agent");
        if (ua != null) {
            ua = ua.replaceAll("[\\r\\n\\t]", " ");   // chống log injection
            if (ua.length() > MAX_USER_AGENT) {
                ua = ua.substring(0, MAX_USER_AGENT);
            }
        }
        return new ClientInfo(ip, ua);
    }
}
