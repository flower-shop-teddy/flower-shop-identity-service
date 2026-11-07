package com.flowershop.identity.service;

import com.flowershop.common.error.BusinessException;
import com.flowershop.common.error.ErrorCode;
import com.flowershop.common.security.CurrentUser;
import com.flowershop.identity.config.IdentityProperties;
import com.flowershop.identity.domain.AuthEventType;
import com.flowershop.identity.domain.RefreshToken;
import com.flowershop.identity.domain.UserAccount;
import com.flowershop.identity.domain.UserStatus;
import com.flowershop.identity.dto.ChangePasswordRequest;
import com.flowershop.identity.dto.LoginRequest;
import com.flowershop.identity.dto.MeResponse;
import com.flowershop.identity.dto.TokenResponse;
import com.flowershop.identity.error.IdentityErrorCode;
import com.flowershop.identity.repository.UserAccountRepository;
import com.flowershop.identity.security.ClientInfo;
import com.flowershop.identity.security.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Đăng nhập, làm mới token, đăng xuất, đổi mật khẩu.
 *
 * BẪY TRANSACTION (quan trọng): nếu viết login trong @Transactional rồi ném exception khi sai mật khẩu,
 * Spring sẽ ROLLBACK luôn việc tăng failed_login_count và dòng nhật ký LOGIN_FAILED -> không bao giờ khóa được ai.
 * Cách làm ở đây: chạy transaction bằng TransactionTemplate, bên trong KHÔNG ném lỗi mà trả về kết quả
 * (thành công hoặc mã lỗi); transaction commit xong mới ném lỗi ra ngoài.
 */
@Slf4j
@Service
public class AuthService {

    /** Kết quả của một transaction: hoặc có giá trị, hoặc có mã lỗi để ném SAU khi commit. */
    private record Outcome<T>(T value, ErrorCode error) {
        static <T> Outcome<T> ok(T value) {
            return new Outcome<>(value, null);
        }

        static <T> Outcome<T> fail(ErrorCode error) {
            return new Outcome<>(null, error);
        }

        T getOrThrow() {
            if (error != null) {
                throw new BusinessException(error);
            }
            return value;
        }
    }

    private final UserAccountRepository users;
    private final RefreshTokenService refreshTokens;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final AuthEventRecorder events;
    private final IdentityProperties props;
    private final Clock clock;
    private final TransactionTemplate tx;
    /**
     * Hash giả để so khi username không tồn tại. Không có bước này thì "user không tồn tại" trả lời nhanh hơn
     * hẳn "sai mật khẩu" (không phải chạy bcrypt) -> đo thời gian phản hồi là dò được username nào có thật.
     */
    private final String dummyHash;

    public AuthService(UserAccountRepository users, RefreshTokenService refreshTokens, TokenService tokenService,
                       PasswordEncoder passwordEncoder, PasswordPolicy passwordPolicy, AuthEventRecorder events,
                       IdentityProperties props, Clock clock, PlatformTransactionManager txManager) {
        this.users = users;
        this.refreshTokens = refreshTokens;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.events = events;
        this.props = props;
        this.clock = clock;
        this.tx = new TransactionTemplate(txManager);
        this.dummyHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    // ------------------------------------------------------------------ login

    public TokenResponse login(LoginRequest req, ClientInfo client) {
        return tx.execute(status -> doLogin(req, client)).getOrThrow();
    }

    private Outcome<TokenResponse> doLogin(LoginRequest req, ClientInfo client) {
        Instant now = clock.instant();
        String loginId = req.loginId().strip();
        Optional<UserAccount> found = LoginIds.isPhone(loginId)
                ? users.findByPhoneForUpdate(loginId)
                : users.findByUsernameForUpdate(LoginIds.normalizeUsername(loginId));

        if (found.isEmpty()) {
            passwordEncoder.matches(req.password(), dummyHash);   // tốn thời gian như khi user có thật
            events.record(AuthEventType.LOGIN_FAILED, null, LoginIds.mask(loginId), client, "UNKNOWN_USER");
            log.info("Login failed: unknown user {}", LoginIds.mask(loginId));
            return Outcome.fail(IdentityErrorCode.INVALID_CREDENTIALS);
        }
        UserAccount user = found.get();

        // Đang khóa thì từ chối luôn, KHÔNG kiểm tra mật khẩu: kẻ tấn công không thể tiếp tục thử trong lúc khóa
        if (user.isLocked(now)) {
            events.record(AuthEventType.LOGIN_FAILED, user, client, "LOCKED");
            return Outcome.fail(IdentityErrorCode.ACCOUNT_LOCKED);
        }

        boolean passwordOk = !passwordPolicy.exceedsMaxBytes(req.password())
                && passwordEncoder.matches(req.password(), user.getPasswordHash());
        if (!passwordOk) {
            boolean lockedNow = user.recordFailedLogin(props.login().maxFailedAttempts(),
                    props.login().lockDuration(), now);
            events.record(AuthEventType.LOGIN_FAILED, user, client, "BAD_PASSWORD");
            if (lockedNow) {
                events.record(AuthEventType.ACCOUNT_LOCKED, user, client, null);
                log.warn("Account locked after too many failed logins: user={}", user.getPublicId());
                return Outcome.fail(IdentityErrorCode.ACCOUNT_LOCKED);
            }
            return Outcome.fail(IdentityErrorCode.INVALID_CREDENTIALS);
        }

        // Kiểm tra trạng thái SAU mật khẩu: không đúng mật khẩu thì không được biết tài khoản bị vô hiệu hóa
        if (!user.isActive()) {
            events.record(AuthEventType.LOGIN_FAILED, user, client, "STATUS_" + user.getStatus());
            return Outcome.fail(user.getStatus() == UserStatus.DISABLED
                    ? IdentityErrorCode.ACCOUNT_DISABLED
                    : IdentityErrorCode.INVALID_CREDENTIALS);
        }

        if (passwordEncoder.upgradeEncoding(user.getPasswordHash())) {
            user.upgradePasswordHash(passwordEncoder.encode(req.password()));
        }
        user.recordSuccessfulLogin(now);
        RefreshTokenService.Issued refresh = refreshTokens.issueNewFamily(user, client);
        events.record(AuthEventType.LOGIN_SUCCESS, user, client, null);
        log.info("Login success: user={} type={}", user.getPublicId(), user.getUserType());
        return Outcome.ok(buildTokens(user, refresh.rawToken()));
    }

    // ---------------------------------------------------------------- refresh

    public TokenResponse refresh(String rawRefreshToken, ClientInfo client) {
        return tx.execute(status -> doRefresh(rawRefreshToken, client)).getOrThrow();
    }

    private Outcome<TokenResponse> doRefresh(String raw, ClientInfo client) {
        Instant now = clock.instant();
        Optional<RefreshToken> found = refreshTokens.findForUpdate(raw);
        if (found.isEmpty()) {
            return Outcome.fail(IdentityErrorCode.INVALID_REFRESH_TOKEN);
        }
        RefreshToken current = found.get();

        if (current.isRevoked()) {
            if (current.getRevokeReason() == RefreshToken.RevokeReason.ROTATED) {
                // Token ĐÃ được đổi rồi mà vẫn có người đem dùng: hoặc kẻ trộm, hoặc chủ thật, ta không biết là ai.
                // An toàn nhất: thu hồi cả family -> cả hai bên đều phải đăng nhập lại.
                refreshTokens.revokeFamily(current, RefreshToken.RevokeReason.REUSE_DETECTED);
                events.record(AuthEventType.TOKEN_REUSE_DETECTED, current.getUserId(), null, client,
                        "family=" + current.getFamilyId());
                log.warn("Refresh token reuse detected: userId={} family={}", current.getUserId(),
                        current.getFamilyId());
            }
            return Outcome.fail(IdentityErrorCode.INVALID_REFRESH_TOKEN);
        }
        if (current.isExpired(now)) {
            return Outcome.fail(IdentityErrorCode.INVALID_REFRESH_TOKEN);
        }

        UserAccount user = users.findById(current.getUserId()).orElseThrow();
        if (!user.isActive() || user.isLocked(now)) {
            refreshTokens.revokeFamily(current, RefreshToken.RevokeReason.ADMIN_ACTION);
            return Outcome.fail(IdentityErrorCode.INVALID_REFRESH_TOKEN);
        }

        RefreshTokenService.Issued next = refreshTokens.rotate(current, client);
        events.record(AuthEventType.TOKEN_REFRESHED, user, client, null);
        return Outcome.ok(buildTokens(user, next.rawToken()));
    }

    // ----------------------------------------------------------------- logout

    /** Luôn trả thành công (kể cả token sai) để không lộ token nào còn hiệu lực. */
    @Transactional
    public void logout(String rawRefreshToken, ClientInfo client) {
        refreshTokens.findForUpdate(rawRefreshToken).ifPresent(token -> {
            refreshTokens.revokeFamily(token, RefreshToken.RevokeReason.LOGOUT);
            events.record(AuthEventType.LOGOUT, token.getUserId(), null, client, null);
        });
    }

    // ------------------------------------------------------- me / đổi mật khẩu

    @Transactional(readOnly = true)
    public MeResponse me() {
        return UserMapper.toMe(currentAccount());
    }

    /** Đổi mật khẩu xong thì mọi phiên (refresh token) cũ bị thu hồi: phải đăng nhập lại ở mọi thiết bị. */
    @Transactional
    public void changePassword(ChangePasswordRequest req, ClientInfo client) {
        UserAccount user = users.findByIdForUpdate(currentAccount().getId()).orElseThrow();
        if (passwordPolicy.exceedsMaxBytes(req.currentPassword())
                || !passwordEncoder.matches(req.currentPassword(), user.getPasswordHash())) {
            throw new BusinessException(IdentityErrorCode.WRONG_CURRENT_PASSWORD);
        }
        passwordPolicy.validate(req.newPassword(), user.loginId());
        if (passwordEncoder.matches(req.newPassword(), user.getPasswordHash())) {
            throw new BusinessException(IdentityErrorCode.WEAK_PASSWORD, "Mật khẩu mới phải khác mật khẩu hiện tại");
        }
        user.changePassword(passwordEncoder.encode(req.newPassword()), clock.instant());
        refreshTokens.revokeAllOfUser(user.getId(), RefreshToken.RevokeReason.PASSWORD_CHANGED);
        events.record(AuthEventType.PASSWORD_CHANGED, user, client, null);
        log.info("Password changed: user={}", user.getPublicId());
    }

    private UserAccount currentAccount() {
        UUID publicId;
        try {
            publicId = UUID.fromString(CurrentUser.require().subject());
        } catch (IllegalArgumentException e) {   // token của service (sub = tên service), không phải người
            throw new BusinessException(IdentityErrorCode.USER_NOT_FOUND);
        }
        return users.findByPublicId(publicId)
                .orElseThrow(() -> new BusinessException(IdentityErrorCode.USER_NOT_FOUND));
    }

    private TokenResponse buildTokens(UserAccount user, String rawRefreshToken) {
        TokenService.IssuedToken access = tokenService.issueAccessToken(user);
        return new TokenResponse("Bearer", access.value(), props.jwt().accessTokenTtl().toSeconds(),
                rawRefreshToken, refreshTokens.ttlSeconds(), user.isMustChangePassword());
    }
}
