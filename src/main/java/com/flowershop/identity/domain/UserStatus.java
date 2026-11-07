package com.flowershop.identity.domain;

public enum UserStatus {
    /** Khách đang đăng ký: đã có tài khoản nhưng chưa tạo xong hồ sơ bên customer-service. Chưa đăng nhập được. */
    PENDING,
    ACTIVE,
    /** Bị quản trị viên vô hiệu hóa. Khác với khóa tạm (locked_until) do nhập sai mật khẩu. */
    DISABLED
}
