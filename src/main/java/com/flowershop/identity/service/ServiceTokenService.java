package com.flowershop.identity.service;

import com.flowershop.common.error.BusinessException;
import com.flowershop.identity.config.IdentityProperties;
import com.flowershop.identity.domain.AuthEventType;
import com.flowershop.identity.domain.ServiceClient;
import com.flowershop.identity.dto.ServiceTokenRequest;
import com.flowershop.identity.dto.ServiceTokenResponse;
import com.flowershop.identity.error.IdentityErrorCode;
import com.flowershop.identity.repository.ServiceClientRepository;
import com.flowershop.identity.security.ClientInfo;
import com.flowershop.identity.security.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Optional;
import java.util.UUID;

/**
 * Cấp service token theo kiểu OAuth2 client_credentials.
 * Cùng các nguyên tắc với đăng nhập người dùng ({@link AuthService}):
 * - sai client id / sai secret / client bị vô hiệu hóa: CÙNG một mã lỗi, không lộ client nào tồn tại;
 * - client không tồn tại vẫn chạy bcrypt với hash giả, để thời gian phản hồi như nhau;
 * - kiểm tra trạng thái SAU secret;
 * - nhật ký được commit TRƯỚC khi ném lỗi (không bị rollback mất).
 * Không khóa client sau nhiều lần sai: secret là chuỗi ngẫu nhiên dài, không đoán được như mật khẩu người dùng,
 * và khóa thì kẻ tấn công chỉ cần gửi sai vài lần là làm sập luồng gọi giữa các service.
 */
@Slf4j
@Service
public class ServiceTokenService {

    private final ServiceClientRepository clients;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final AuthEventRecorder events;
    private final IdentityProperties props;
    private final TransactionTemplate tx;
    private final String dummyHash;

    public ServiceTokenService(ServiceClientRepository clients, TokenService tokenService,
                               PasswordEncoder passwordEncoder, AuthEventRecorder events, IdentityProperties props,
                               PlatformTransactionManager txManager) {
        this.clients = clients;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
        this.events = events;
        this.props = props;
        this.tx = new TransactionTemplate(txManager);
        this.dummyHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    public ServiceTokenResponse issue(ServiceTokenRequest req, ClientInfo client) {
        Optional<ServiceTokenResponse> result = tx.execute(status -> doIssue(req, client));
        return result.orElseThrow(() -> new BusinessException(IdentityErrorCode.INVALID_CLIENT_CREDENTIALS));
    }

    private Optional<ServiceTokenResponse> doIssue(ServiceTokenRequest req, ClientInfo client) {
        // clientId đã qua @Pattern ở DTO: chỉ chữ thường, số, gạch ngang -> an toàn để ghi log/DB
        String clientId = req.clientId();
        Optional<ServiceClient> found = clients.findByClientId(clientId);

        if (found.isEmpty()) {
            passwordEncoder.matches(req.clientSecret(), dummyHash);
            return deny(clientId, "UNKNOWN_CLIENT", client);
        }
        ServiceClient sc = found.get();
        if (!passwordEncoder.matches(req.clientSecret(), sc.getSecretHash())) {
            return deny(clientId, "BAD_SECRET", client);
        }
        if (!sc.isActive()) {
            return deny(clientId, "STATUS_" + sc.getStatus(), client);
        }

        TokenService.IssuedToken token = tokenService.issueServiceToken(sc.getClientId(), sc.permissionCodes());
        events.record(AuthEventType.SERVICE_TOKEN_ISSUED, null, null, client, "client=" + clientId);
        log.debug("Service token issued: client={} perms={}", clientId, sc.permissionCodes());
        return Optional.of(new ServiceTokenResponse("Bearer", token.value(),
                props.jwt().serviceTokenTtl().toSeconds()));
    }

    private Optional<ServiceTokenResponse> deny(String clientId, String reason, ClientInfo client) {
        events.record(AuthEventType.SERVICE_TOKEN_DENIED, null, null, client, "client=" + clientId + " " + reason);
        log.warn("Service token denied: client={} reason={}", clientId, reason);
        return Optional.empty();
    }
}
