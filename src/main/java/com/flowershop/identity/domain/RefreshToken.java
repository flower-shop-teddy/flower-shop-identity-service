package com.flowershop.identity.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/** Một refresh token. Chỉ lưu hash; token gốc chỉ trả cho client đúng một lần lúc tạo. */
@Entity
@Table(name = "refresh_token")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {

    public enum RevokeReason {
        /** Đã dùng để đổi lấy token mới (bình thường). */
        ROTATED,
        LOGOUT,
        /** Token đã ROTATED bị đem dùng lại: dấu hiệu bị đánh cắp, thu hồi cả family. */
        REUSE_DETECTED,
        PASSWORD_CHANGED,
        ADMIN_ACTION
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private Long userId;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64, updatable = false)
    private String tokenHash;

    @Column(name = "family_id", nullable = false, updatable = false)
    private UUID familyId;

    @Column(name = "issued_at", nullable = false, updatable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "revoke_reason", length = 30)
    private RevokeReason revokeReason;

    @Column(name = "replaced_by_id")
    private Long replacedById;

    @Column(name = "client_ip", length = 45, updatable = false)
    private String clientIp;

    @Column(name = "user_agent", updatable = false)
    private String userAgent;

    public static RefreshToken issue(Long userId, String tokenHash, UUID familyId, Instant now, Instant expiresAt,
                                     String clientIp, String userAgent) {
        RefreshToken t = new RefreshToken();
        t.userId = userId;
        t.tokenHash = tokenHash;
        t.familyId = familyId;
        t.issuedAt = now;
        t.expiresAt = expiresAt;
        t.clientIp = clientIp;
        t.userAgent = userAgent;
        return t;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }

    public void rotateTo(RefreshToken next, Instant now) {
        this.revokedAt = now;
        this.revokeReason = RevokeReason.ROTATED;
        this.replacedById = next.getId();
    }
}
