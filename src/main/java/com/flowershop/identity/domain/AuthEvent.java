package com.flowershop.identity.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Immutable;

import java.time.Instant;

/** Nhật ký bảo mật, chỉ thêm. @Immutable: Hibernate không bao giờ sinh câu UPDATE cho entity này. */
@Entity
@Immutable
@Table(name = "auth_event")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 40)
    private AuthEventType eventType;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "login_id_masked", length = 60)
    private String loginIdMasked;

    @Column(length = 100)
    private String actor;

    @Column(length = 255)
    private String detail;

    @Column(name = "client_ip", length = 45)
    private String clientIp;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "correlation_id", length = 64)
    private String correlationId;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    public static AuthEvent of(AuthEventType type, Long userId, String loginIdMasked, String actor, String detail,
                               String clientIp, String userAgent, String correlationId, Instant now) {
        AuthEvent e = new AuthEvent();
        e.eventType = type;
        e.userId = userId;
        e.loginIdMasked = loginIdMasked;
        e.actor = actor;
        e.detail = detail;
        e.clientIp = clientIp;
        e.userAgent = userAgent;
        e.correlationId = correlationId;
        e.occurredAt = now;
        return e;
    }
}
