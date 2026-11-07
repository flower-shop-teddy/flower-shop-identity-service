package com.flowershop.identity.service;

import com.flowershop.common.error.BusinessException;
import com.flowershop.identity.error.IdentityErrorCode;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * Luật mật khẩu + sinh mật khẩu tạm.
 * Giới hạn 72 BYTE: bcrypt chỉ dùng 72 byte đầu, phần sau bị bỏ qua âm thầm
 * (mật khẩu "aaa...a" 80 ký tự và "aaa...a" 72 ký tự + "xyz" sẽ bị coi là một). Chặn từ đầu cho rõ ràng.
 */
@Component
public class PasswordPolicy {

    public static final int MIN_LENGTH = 8;
    public static final int MAX_BYTES = 72;

    private static final String UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";   // bỏ I, O dễ nhầm với 1, 0
    private static final String LOWER = "abcdefghijkmnpqrstuvwxyz";   // bỏ l, o
    private static final String DIGITS = "23456789";                  // bỏ 0, 1
    private static final SecureRandom RANDOM = new SecureRandom();

    public void validate(String password, String loginId) {
        if (password.length() < MIN_LENGTH) {
            throw weak("Mật khẩu tối thiểu " + MIN_LENGTH + " ký tự");
        }
        if (exceedsMaxBytes(password)) {
            throw weak("Mật khẩu quá dài");
        }
        if (password.chars().noneMatch(Character::isLetter) || password.chars().noneMatch(Character::isDigit)) {
            throw weak("Mật khẩu phải có cả chữ và số");
        }
        if (loginId != null && password.toLowerCase(Locale.ROOT).contains(loginId.toLowerCase(Locale.ROOT))) {
            throw weak("Mật khẩu không được chứa tên đăng nhập hoặc số điện thoại");
        }
    }

    public boolean exceedsMaxBytes(String password) {
        return password.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES;
    }

    /** 12 ký tự, chắc chắn có chữ hoa, chữ thường và số. SecureRandom, không dùng Random. */
    public String generateTemporary() {
        String all = UPPER + LOWER + DIGITS;
        char[] chars = new char[12];
        chars[0] = UPPER.charAt(RANDOM.nextInt(UPPER.length()));
        chars[1] = LOWER.charAt(RANDOM.nextInt(LOWER.length()));
        chars[2] = DIGITS.charAt(RANDOM.nextInt(DIGITS.length()));
        for (int i = 3; i < chars.length; i++) {
            chars[i] = all.charAt(RANDOM.nextInt(all.length()));
        }
        for (int i = chars.length - 1; i > 0; i--) {   // xáo trộn để 3 ký tự đầu không cố định loại
            int j = RANDOM.nextInt(i + 1);
            char t = chars[i];
            chars[i] = chars[j];
            chars[j] = t;
        }
        return new String(chars);
    }

    private static BusinessException weak(String message) {
        return new BusinessException(IdentityErrorCode.WEAK_PASSWORD, message);
    }
}
