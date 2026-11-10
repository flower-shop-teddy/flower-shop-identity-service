package com.flowershop.identity.config;

import com.flowershop.identity.client.ServiceTokenProvider;
import com.flowershop.identity.domain.Permission;
import com.flowershop.identity.domain.ServiceClient;
import com.flowershop.identity.repository.PermissionRepository;
import com.flowershop.identity.repository.ServiceClientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Tạo service client từ cấu hình identity.service-clients lúc khởi động, giống {@link AdminBootstrap}:
 * <ul>
 *   <li>chưa có thì tạo, ĐÃ CÓ thì bỏ qua (restart không ghi đè secret/permission đang dùng);</li>
 *   <li>cấu hình sai (secret ngắn, permission không tồn tại...) thì KHÔNG khởi động (fail fast).</li>
 * </ul>
 * Secret lấy từ biến môi trường, vd {@code identity.service-clients[0].secret=${ORDER_SERVICE_CLIENT_SECRET}}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ServiceClientBootstrap implements ApplicationRunner {

    private static final Pattern CLIENT_ID = Pattern.compile("^[a-z][a-z0-9-]{2,49}$");
    /** 32 ký tự ngẫu nhiên: không thể dò. Tối đa 72 byte vì bcrypt bỏ qua phần sau. */
    private static final int MIN_SECRET_LENGTH = 32;
    private static final int MAX_SECRET_BYTES = 72;

    private final IdentityProperties props;
    private final ServiceClientRepository clients;
    private final PermissionRepository permissions;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        for (IdentityProperties.ServiceClientSeed seed : props.serviceClients()) {
            validate(seed);
            if (clients.existsByClientId(seed.clientId())) {
                log.debug("Service client '{}' exists, bootstrap skipped", seed.clientId());
                continue;
            }
            clients.save(ServiceClient.create(seed.clientId(), passwordEncoder.encode(seed.secret()),
                    resolvePermissions(seed)));
            log.warn("Service client '{}' created with permissions {}", seed.clientId(), seed.permissions());
        }
    }

    private static void validate(IdentityProperties.ServiceClientSeed seed) {
        if (!CLIENT_ID.matcher(seed.clientId()).matches()) {
            throw new IllegalStateException("client-id không hợp lệ: " + seed.clientId());
        }
        // Tên này là sub của token identity tự ký cho chính mình: không cho service khác mạo danh
        if (ServiceTokenProvider.SERVICE_NAME.equals(seed.clientId())) {
            throw new IllegalStateException("client-id '" + seed.clientId() + "' được dành riêng cho identity-service");
        }
        if (seed.secret().length() < MIN_SECRET_LENGTH
                || seed.secret().getBytes(StandardCharsets.UTF_8).length > MAX_SECRET_BYTES) {
            throw new IllegalStateException("Secret của '" + seed.clientId() + "' phải dài " + MIN_SECRET_LENGTH
                    + " ký tự đến " + MAX_SECRET_BYTES + " byte (tạo: openssl rand -base64 36)");
        }
    }

    private List<Permission> resolvePermissions(IdentityProperties.ServiceClientSeed seed) {
        Set<String> wanted = new TreeSet<>(seed.permissions());
        List<Permission> found = permissions.findByCodeIn(wanted);
        if (found.size() != wanted.size()) {
            Set<String> missing = new TreeSet<>(wanted);
            found.forEach(p -> missing.remove(p.getCode()));
            throw new IllegalStateException("Permission không tồn tại cho '" + seed.clientId() + "': " + missing);
        }
        return found;
    }
}
