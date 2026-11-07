package com.flowershop.identity.config;

import com.flowershop.identity.domain.Role;
import com.flowershop.identity.domain.UserAccount;
import com.flowershop.identity.repository.RoleRepository;
import com.flowershop.identity.repository.UserAccountRepository;
import com.flowershop.identity.service.PasswordPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.Locale;
import java.util.Set;

/**
 * Bài toán "con gà - quả trứng": muốn tạo tài khoản phải có ADMIN, mà ADMIN đầu tiên lấy đâu ra?
 * Lúc khởi động, nếu hệ thống CHƯA có ADMIN nào thì tạo một ADMIN từ BOOTSTRAP_ADMIN_USERNAME/PASSWORD.
 * Đã có ADMIN thì bỏ qua (khởi động lại không ghi đè gì). ADMIN này bị buộc đổi mật khẩu ở lần đăng nhập đầu.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AdminBootstrap implements ApplicationRunner {

    private final IdentityProperties props;
    private final UserAccountRepository users;
    private final RoleRepository roles;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final Clock clock;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        IdentityProperties.BootstrapAdmin cfg = props.bootstrapAdmin();
        if (cfg.username() == null || cfg.username().isBlank()) {
            return;
        }
        if (users.existsByRoles_Code(Role.ADMIN)) {
            log.debug("Admin bootstrap skipped: an ADMIN already exists");
            return;
        }
        String username = cfg.username().strip().toLowerCase(Locale.ROOT);
        if (users.existsByUsername(username)) {
            log.warn("Admin bootstrap skipped: username '{}' exists but is not ADMIN", username);
            return;
        }
        passwordPolicy.validate(cfg.password(), username);
        Role admin = roles.findByCode(Role.ADMIN).orElseThrow();
        users.save(UserAccount.newStaff(username, passwordEncoder.encode(cfg.password()), Set.of(admin),
                clock.instant()));
        log.warn("Bootstrap ADMIN '{}' created. Đăng nhập và đổi mật khẩu ngay.", username);
    }
}
