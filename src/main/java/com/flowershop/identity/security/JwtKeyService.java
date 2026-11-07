package com.flowershop.identity.security;

import com.flowershop.identity.config.IdentityProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Quản lý cặp khóa RSA dùng để KÝ access token.
 * <ul>
 *   <li>Private key: chỉ identity-service giữ (môi trường thật nằm trong Vault/KMS, truyền vào qua JWT_PRIVATE_KEY).</li>
 *   <li>Public key: ai cũng được xem qua /.well-known/jwks.json. Service khác dùng nó để kiểm tra chữ ký,
 *       nên KHÔNG service nào khác giữ bí mật gì để có thể giả mạo token.</li>
 *   <li>kid (key id) ghi trong header của JWT: service nhận token biết dùng khóa nào trong JWKS để kiểm tra.</li>
 * </ul>
 * Xoay khóa: tạo khóa mới làm khóa ký, đưa public key của khóa cũ vào identity.jwt.retired-public-keys
 * để token cũ (còn hạn tối đa 15 phút) vẫn kiểm tra được. Sau một thời gian thì bỏ khóa cũ ra.
 */
@Slf4j
@Component
public class JwtKeyService {

    private final RSAKey signingKey;
    private final JWKSet publicJwkSet;

    public JwtKeyService(IdentityProperties props) {
        IdentityProperties.Jwt cfg = props.jwt();
        this.signingKey = loadOrGenerate(cfg);

        List<JWK> publicKeys = new ArrayList<>();
        publicKeys.add(signingKey.toPublicJWK());
        Map<String, String> retired = cfg.retiredPublicKeys() == null ? Map.of() : cfg.retiredPublicKeys();
        retired.forEach((kid, pem) -> publicKeys.add(new RSAKey.Builder(parsePublicKey(pem))
                .keyID(kid).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build()));
        this.publicJwkSet = new JWKSet(publicKeys);
        log.info("JWT signing key kid={}, JWKS publishes {} key(s)", signingKey.getKeyID(), publicKeys.size());
    }

    /** Khóa ký hiện tại (có private key). Không bao giờ trả ra ngoài. */
    public RSAKey signingKey() {
        return signingKey;
    }

    /** Chỉ chứa public key: an toàn để công khai. */
    public JWKSet publicJwkSet() {
        return publicJwkSet;
    }

    private static RSAKey loadOrGenerate(IdentityProperties.Jwt cfg) {
        if (cfg.privateKey() != null && !cfg.privateKey().isBlank()) {
            if (cfg.keyId() == null || cfg.keyId().isBlank()) {
                throw new IllegalStateException("Thiếu identity.jwt.key-id (JWT_KEY_ID) đi kèm private key");
            }
            RSAPrivateCrtKey privateKey = parsePrivateKey(cfg.privateKey());
            return new RSAKey.Builder(publicFrom(privateKey)).privateKey(privateKey)
                    .keyID(cfg.keyId()).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();
        }
        if (!cfg.generateDevKey()) {
            // Fail fast: thà không khởi động còn hơn chạy với khóa tạm trên môi trường thật
            throw new IllegalStateException("Thiếu JWT_PRIVATE_KEY. Chỉ profile local mới được tự sinh khóa.");
        }
        log.warn("Đang dùng khóa JWT TỰ SINH (chỉ dành cho máy dev). Restart là mọi token cũ mất hiệu lực.");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) pair.getPublic()).privateKey(pair.getPrivate())
                    .keyID("dev-" + UUID.randomUUID().toString().substring(0, 8))
                    .keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static RSAPrivateCrtKey parsePrivateKey(String pem) {
        try {
            byte[] der = decodePem(pem, "PRIVATE KEY");
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
            if (!(key instanceof RSAPrivateCrtKey crt)) {
                throw new IllegalStateException("Private key phải là RSA (PKCS#8)");
            }
            return crt;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("JWT_PRIVATE_KEY không hợp lệ (cần PEM PKCS#8 RSA)", e);
        }
    }

    private static RSAPublicKey parsePublicKey(String pem) {
        try {
            byte[] der = decodePem(pem, "PUBLIC KEY");
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Public key cũ trong retired-public-keys không hợp lệ", e);
        }
    }

    private static RSAPublicKey publicFrom(RSAPrivateCrtKey privateKey) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] decodePem(String pem, String type) {
        String body = pem.replace("-----BEGIN " + type + "-----", "")
                .replace("-----END " + type + "-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }
}
