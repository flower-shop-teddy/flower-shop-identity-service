package com.flowershop.identity.error;

import com.flowershop.common.error.ErrorCode;
import org.springframework.http.HttpStatus;

public enum IdentityErrorCode implements ErrorCode {
    WEAK_PASSWORD("IDN-400-001", HttpStatus.BAD_REQUEST, "Mật khẩu chưa đủ mạnh"),
    WRONG_CURRENT_PASSWORD("IDN-400-002", HttpStatus.BAD_REQUEST, "Mật khẩu hiện tại không đúng"),
    INVALID_ROLE("IDN-400-003", HttpStatus.BAD_REQUEST, "Role không hợp lệ"),
    // Sai username hay sai mật khẩu đều trả CÙNG một mã: kẻ tấn công không dò được username nào tồn tại
    INVALID_CREDENTIALS("IDN-401-001", HttpStatus.UNAUTHORIZED, "Thông tin đăng nhập không đúng"),
    INVALID_REFRESH_TOKEN("IDN-401-002", HttpStatus.UNAUTHORIZED,
            "Phiên đăng nhập không hợp lệ hoặc đã hết hạn, vui lòng đăng nhập lại"),
    // Sai client id, sai secret hay client bị vô hiệu hóa đều cùng một mã (như INVALID_CREDENTIALS)
    INVALID_CLIENT_CREDENTIALS("IDN-401-003", HttpStatus.UNAUTHORIZED, "Thông tin xác thực service không đúng"),
    ACCOUNT_DISABLED("IDN-403-001", HttpStatus.FORBIDDEN, "Tài khoản đã bị vô hiệu hóa"),
    CANNOT_MODIFY_SELF("IDN-403-002", HttpStatus.FORBIDDEN, "Không được tự thay đổi quyền hoặc trạng thái của chính mình"),
    ADMIN_REQUIRED("IDN-403-003", HttpStatus.FORBIDDEN, "Chỉ ADMIN mới được thao tác trên tài khoản hoặc role ADMIN"),
    USER_NOT_FOUND("IDN-404-001", HttpStatus.NOT_FOUND, "Không tìm thấy tài khoản"),
    USERNAME_ALREADY_EXISTS("IDN-409-001", HttpStatus.CONFLICT, "Username đã tồn tại"),
    PHONE_ALREADY_REGISTERED("IDN-409-002", HttpStatus.CONFLICT, "Số điện thoại đã được đăng ký tài khoản"),
    CUSTOMER_PROFILE_EXISTS("IDN-409-003", HttpStatus.CONFLICT,
            "Số điện thoại đã có hồ sơ tại cửa hàng, vui lòng liên hệ cửa hàng để kích hoạt tài khoản"),
    EMAIL_ALREADY_USED("IDN-409-004", HttpStatus.CONFLICT, "Email đã được sử dụng"),
    NOT_A_STAFF_ACCOUNT("IDN-422-001", HttpStatus.UNPROCESSABLE_ENTITY, "Chỉ gán role cho tài khoản nhân viên"),
    ACCOUNT_LOCKED("IDN-423-001", HttpStatus.LOCKED,
            "Tài khoản tạm khóa do nhập sai mật khẩu nhiều lần, vui lòng thử lại sau"),
    CUSTOMER_SERVICE_UNAVAILABLE("IDN-503-001", HttpStatus.SERVICE_UNAVAILABLE,
            "Chưa thể đăng ký lúc này, vui lòng thử lại sau");

    private final String code;
    private final HttpStatus status;
    private final String defaultMessage;

    IdentityErrorCode(String code, HttpStatus status, String defaultMessage) {
        this.code = code;
        this.status = status;
        this.defaultMessage = defaultMessage;
    }

    @Override public String code() { return code; }
    @Override public HttpStatus status() { return status; }
    @Override public String defaultMessage() { return defaultMessage; }
}
