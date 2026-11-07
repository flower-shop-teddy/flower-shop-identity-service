package com.flowershop.identity.service;

import com.flowershop.identity.config.IdentityProperties;
import com.flowershop.identity.domain.RefreshToken;
import com.flowershop.identity.domain.UserAccount;
import com.flowershop.identity.repository.RefreshTokenRepository;
import com.flowershop.identity.security.ClientInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

/**
 * Refresh token dạng OPAQUE (chuỗi ngẫu nhiên, không phải JWT): chỉ identity-service hiểu được,
 * thu hồi được ngay bằng cách đánh dấu trong DB.
 *
 * Vì sao DB lưu SHA-256 mà không lưu bcrypt như mật khẩu? Token có 256 bit ngẫu nhiên nên không dò được,
 * không cần thuật toán chậm; và cần TÌM theo hash (bcrypt có salt ngẫu nhiên nên không tìm được).
 */
@Component
@RequiredArgsConstructor
public class RefreshTokenService {

    /** Token gốc (trả cho client) + entity đã lưu. */
    public record Issued(String rawToken, RefreshToken entity) {
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final RefreshTokenRepository repository;
    private final IdentityProperties props;
    private final Clock clock;

    /** Đăng nhập mới: mở một family mới. */
    @Transactional(propagation = Propagation.MANDATORY)
    public Issued issueNewFamily(UserAccount user, ClientInfo client) {
        return issue(user.getId(), UUID.randomUUID(), client);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public Optional<RefreshToken> findForUpdate(String rawToken) {
        return repository.findByTokenHashForUpdate(hash(rawToken));
    }

    /** Thu hồi token đang dùng, cấp token mới CÙNG family. */
    @Transactional(propagation = Propagation.MANDATORY)
    public Issued rotate(RefreshToken current, ClientInfo client) {
        Issued next = issue(current.getUserId(), current.getFamilyId(), client);
        current.rotateTo(next.entity(), clock.instant());
        return next;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void revokeFamily(RefreshToken token, RefreshToken.RevokeReason reason) {
        repository.revokeFamily(token.getFamilyId(), reason, clock.instant());
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void revokeAllOfUser(Long userId, RefreshToken.RevokeReason reason) {
        repository.revokeAllOfUser(userId, reason, clock.instant());
    }

    public long ttlSeconds() {
        return props.refreshToken().ttl().toSeconds();
    }

    private Issued issue(Long userId, UUID familyId, ClientInfo client) {
        byte[] bytes = new byte[32];   // 256 bit
        RANDOM.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Instant now = clock.instant();
        RefreshToken entity = repository.saveAndFlush(RefreshToken.issue(userId, hash(raw), familyId, now,
                now.plus(props.refreshToken().ttl()), client.ip(), client.userAgent()));
        return new Issued(raw, entity);
    }

    static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
