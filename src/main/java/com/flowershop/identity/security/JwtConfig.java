package com.flowershop.identity.security;

import com.flowershop.identity.config.IdentityProperties;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.util.List;

/**
 * identity-service vừa KÝ token (JwtEncoder) vừa KIỂM TRA token cho API của chính nó (JwtDecoder).
 * Service khác kiểm tra qua JWKS (gọi HTTP); ở đây có sẵn khóa trong bộ nhớ nên không cần.
 */
@Configuration
public class JwtConfig {

    @Bean
    public JwtEncoder jwtEncoder(JwtKeyService keys) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<SecurityContext>(new JWKSet(keys.signingKey())));
    }

    @Bean
    public JwtDecoder jwtDecoder(JwtKeyService keys, IdentityProperties props) throws Exception {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(keys.signingKey().toRSAPublicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        // Mặc định chỉ kiểm tra exp/nbf. Thêm: đúng bên phát hành (iss) và đúng đối tượng sử dụng (aud).
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(props.jwt().issuer()),
                new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                        aud -> aud != null && aud.contains(props.jwt().audience()))));
        return decoder;
    }
}
