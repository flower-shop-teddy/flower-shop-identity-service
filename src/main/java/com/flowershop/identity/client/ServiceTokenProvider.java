package com.flowershop.identity.client;

import com.flowershop.identity.security.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/** Token để identity-service gọi customer-service. Dùng lại tới khi còn dưới 1 phút thì ký token mới. */
@Component
@RequiredArgsConstructor
public class ServiceTokenProvider {

    public static final String SERVICE_NAME = "identity-service";
    /** Least privilege: chỉ đúng quyền cần dùng, không phải mọi quyền. */
    static final List<String> PERMISSIONS = List.of("customer:create");
    private static final Duration RENEW_BEFORE = Duration.ofMinutes(1);

    private final TokenService tokenService;
    private final Clock clock;
    private final AtomicReference<TokenService.IssuedToken> cached = new AtomicReference<>();

    public String get() {
        TokenService.IssuedToken token = cached.get();
        if (token == null || token.expiresAt().minus(RENEW_BEFORE).isBefore(clock.instant())) {
            token = tokenService.issueServiceToken(SERVICE_NAME, PERMISSIONS);
            cached.set(token);
        }
        return token.value();
    }
}
