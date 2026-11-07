package com.flowershop.identity.service;

import com.flowershop.common.security.AuthenticatedUser;
import com.flowershop.common.security.CurrentUser;
import com.flowershop.common.web.CorrelationId;
import com.flowershop.identity.domain.AuthEvent;
import com.flowershop.identity.domain.AuthEventType;
import com.flowershop.identity.domain.UserAccount;
import com.flowershop.identity.repository.AuthEventRepository;
import com.flowershop.identity.security.ClientInfo;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;

/**
 * Ghi nhật ký bảo mật vào bảng auth_event, TRONG CÙNG transaction với thay đổi nghiệp vụ:
 * thay đổi được lưu thì nhật ký được lưu, rollback thì cả hai cùng mất (không có nhật ký "ma").
 */
@Component
@RequiredArgsConstructor
public class AuthEventRecorder {

    private final AuthEventRepository repository;
    private final Clock clock;

    @Transactional(propagation = Propagation.MANDATORY)
    public void record(AuthEventType type, UserAccount user, ClientInfo client, String detail) {
        record(type, user == null ? null : user.getId(),
                user == null ? null : LoginIds.mask(user.loginId()), client, detail);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void record(AuthEventType type, Long userId, String loginIdMasked, ClientInfo client, String detail) {
        String actor = CurrentUser.get().map(AuthenticatedUser::subject).orElse(null);
        ClientInfo c = client == null ? ClientInfo.UNKNOWN : client;
        repository.save(AuthEvent.of(type, userId, loginIdMasked, actor, detail,
                c.ip(), c.userAgent(), MDC.get(CorrelationId.MDC_KEY), clock.instant()));
    }
}
