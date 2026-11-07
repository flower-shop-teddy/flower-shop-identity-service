package com.flowershop.identity.service;

import com.flowershop.common.util.DataMasking;

import java.util.Locale;
import java.util.regex.Pattern;

/** Chuẩn hóa và che loginId. SĐT -> khách hàng, còn lại -> username nhân viên (luôn chữ thường). */
final class LoginIds {

    static final Pattern PHONE = Pattern.compile("^0\\d{9}$");

    private LoginIds() {
    }

    static boolean isPhone(String loginId) {
        return PHONE.matcher(loginId).matches();
    }

    static String normalizeUsername(String username) {
        return username.strip().toLowerCase(Locale.ROOT);
    }

    /** Ghi log/nhật ký: SĐT chỉ giữ 3 số cuối, username giữ 2 ký tự đầu. */
    static String mask(String loginId) {
        if (loginId == null) {
            return null;
        }
        String id = loginId.strip();
        if (id.length() > 50) {
            id = id.substring(0, 50);
        }
        if (isPhone(id)) {
            return DataMasking.maskTail(id, 3);
        }
        return id.length() <= 2 ? "*".repeat(id.length()) : id.substring(0, 2) + "***";
    }
}
