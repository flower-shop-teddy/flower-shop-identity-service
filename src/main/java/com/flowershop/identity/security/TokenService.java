package com.flowershop.identity.security;

import com.flowershop.common.security.AuthClaims;
import com.flowershop.common.security.UserType;
import com.flowershop.identity.config.IdentityProperties;
import com.flowershop.identity.domain.UserAccount;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Tạo và ký access token (JWT, RS256). */
@Component
@RequiredArgsConstructor
public class TokenService {

    public record IssuedToken(String value, Instant expiresAt) {
    }

    private final JwtEncoder encoder;
    private final JwtKeyService keys;
    private final IdentityProperties props;
    private final Clock clock;

    /**
     * Token cho người dùng. Permission được "chụp" vào token lúc cấp: đổi role thì token cũ vẫn mang quyền cũ
     * cho tới khi hết hạn (15 phút). Đây là cái giá của JWT stateless, đổi lại service không phải hỏi DB mỗi request.
     */
    public IssuedToken issueAccessToken(UserAccount user) {
        boolean mustChangePassword = user.isMustChangePassword();
        JwtClaimsSet.Builder claims = baseClaims(user.getPublicId().toString(), props.jwt().accessTokenTtl())
                .claim(AuthClaims.USER_TYPE, user.getUserType().name())
                .claim(AuthClaims.ROLES, user.roleCodes())
                // Phải đổi mật khẩu trước: token không mang quyền gì, chỉ gọi được /auth/change-password và /auth/me
                .claim(AuthClaims.PERMS, mustChangePassword ? List.of() : user.permissionCodes());
        if (user.getCustomerId() != null) {
            claims.claim(AuthClaims.CUSTOMER_ID, user.getCustomerId());
        }
        if (mustChangePassword) {
            claims.claim(AuthClaims.PWD_CHANGE_REQUIRED, true);
        }
        return sign(claims.build());
    }

    /**
     * Token cho chính identity-service khi gọi service khác (vd tạo hồ sơ khách lúc đăng ký).
     * Hệ thống lớn thường dùng OAuth2 client_credentials hoặc mTLS qua service mesh; ở đây identity là bên
     * phát hành token nên tự ký luôn, chỉ mang đúng permission cần dùng (least privilege).
     */
    public IssuedToken issueServiceToken(String serviceName, List<String> permissions) {
        JwtClaimsSet claims = baseClaims(serviceName, props.jwt().serviceTokenTtl())
                .claim(AuthClaims.USER_TYPE, UserType.SERVICE.name())
                .claim(AuthClaims.ROLES, List.of())
                .claim(AuthClaims.PERMS, permissions)
                .build();
        return sign(claims);
    }

    private JwtClaimsSet.Builder baseClaims(String subject, Duration ttl) {
        Instant now = clock.instant();
        return JwtClaimsSet.builder()
                .issuer(props.jwt().issuer())
                .audience(List.of(props.jwt().audience()))
                .subject(subject)
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(ttl))
                .id(UUID.randomUUID().toString());   // jti: mã duy nhất của token, dùng để truy vết/denylist sau này
    }

    private IssuedToken sign(JwtClaimsSet claims) {
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(keys.signingKey().getKeyID()).build();
        String value = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new IssuedToken(value, claims.getExpiresAt());
    }
}
