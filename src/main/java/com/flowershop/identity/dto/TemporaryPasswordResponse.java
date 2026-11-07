package com.flowershop.identity.dto;

/**
 * Mật khẩu tạm chỉ hiện ĐÚNG MỘT LẦN trong response này, DB chỉ lưu hash.
 * Thực tế ngân hàng gửi qua kênh riêng (SMS/email) chứ không hiện trên màn hình quản trị.
 */
public record TemporaryPasswordResponse(UserResponse user, String temporaryPassword) {
    @Override
    public String toString() {
        return "TemporaryPasswordResponse[user=" + user.publicId() + ", temporaryPassword=***]";
    }
}
