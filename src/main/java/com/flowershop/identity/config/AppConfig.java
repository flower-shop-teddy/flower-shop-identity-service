package com.flowershop.identity.config;

import com.flowershop.common.security.JwtAuditorAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.util.Map;

@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class AppConfig {

    /** created_by / updated_by = sub của người đang gọi API, không có thì "system". */
    @Bean
    public AuditorAware<String> auditorProvider() {
        return new JwtAuditorAware();
    }

    /** Lấy giờ qua Clock thay vì Instant.now(): test có thể cố định thời gian. */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * Hash lưu dạng {bcrypt}$2a$12$...: tiền tố cho biết thuật toán.
     * Sau này chuyển sang argon2 chỉ cần đổi idForEncode; hash bcrypt cũ vẫn kiểm tra được
     * và sẽ được băm lại khi user đăng nhập (upgradeEncoding).
     */
    @Bean
    public PasswordEncoder passwordEncoder(IdentityProperties props) {
        String idForEncode = "bcrypt";
        return new DelegatingPasswordEncoder(idForEncode,
                Map.of(idForEncode, new BCryptPasswordEncoder(props.password().bcryptStrength())));
    }
}
