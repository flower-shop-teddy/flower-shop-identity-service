package com.flowershop.identity.service;

import com.flowershop.common.error.BusinessException;
import com.flowershop.common.util.DataMasking;
import com.flowershop.identity.client.CustomerClient;
import com.flowershop.identity.domain.AuthEventType;
import com.flowershop.identity.domain.Role;
import com.flowershop.identity.domain.UserAccount;
import com.flowershop.identity.dto.RegisterRequest;
import com.flowershop.identity.dto.RegisterResponse;
import com.flowershop.identity.error.IdentityErrorCode;
import com.flowershop.identity.repository.RoleRepository;
import com.flowershop.identity.repository.UserAccountRepository;
import com.flowershop.identity.security.ClientInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.util.UUID;

/**
 * Khách tự đăng ký. Dữ liệu nằm ở HAI service (tài khoản ở identity, hồ sơ ở customer), không có transaction
 * nào bao được cả hai DB -> làm theo kiểu SAGA: chia thành các bước, mỗi bước một transaction cục bộ,
 * bước sau lỗi thì chạy bước BÙ TRỪ để hoàn tác bước trước.
 *
 * <pre>
 * B1 identity : tạo tài khoản PENDING (giữ chỗ SĐT, UNIQUE ở DB chặn hai người đăng ký cùng lúc)
 * B2 customer : tạo hồ sơ khách hàng (gọi HTTP)          -- lỗi -> bù trừ: xóa tài khoản PENDING
 * B3 identity : gắn customer_id, ACTIVE, gán role CUSTOMER
 * </pre>
 *
 * Giới hạn đã biết (để học tiếp ở giai đoạn sau):
 * - B2 hết thời gian chờ nhưng thực ra customer-service ĐÃ tạo hồ sơ -> hồ sơ "mồ côi", khách đăng ký lại
 *   sẽ nhận lỗi "SĐT đã có hồ sơ". Cách chữa: Idempotency-Key, hoặc outbox + message broker (Kafka).
 * - Chưa có OTP nên không chứng minh được người đăng ký là chủ SĐT; vì vậy SĐT đã có hồ sơ thì KHÔNG tự gắn vào.
 */
@Slf4j
@Service
public class RegistrationService {

    private final UserAccountRepository users;
    private final RoleRepository roles;
    private final CustomerClient customerClient;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final AuthEventRecorder events;
    private final Clock clock;
    private final TransactionTemplate tx;

    public RegistrationService(UserAccountRepository users, RoleRepository roles, CustomerClient customerClient,
                               PasswordEncoder passwordEncoder, PasswordPolicy passwordPolicy,
                               AuthEventRecorder events, Clock clock, PlatformTransactionManager txManager) {
        this.users = users;
        this.roles = roles;
        this.customerClient = customerClient;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.events = events;
        this.clock = clock;
        this.tx = new TransactionTemplate(txManager);
    }

    public RegisterResponse register(RegisterRequest req, ClientInfo client) {
        passwordPolicy.validate(req.password(), req.phone());
        String maskedPhone = DataMasking.maskTail(req.phone(), 3);

        // B1. Không gọi service khác khi đang mở transaction: giữ kết nối DB trong lúc chờ HTTP là lãng phí pool
        Long accountId = tx.execute(status -> createPendingAccount(req));
        log.info("Registration step 1/3 done: pending account id={} phone={}", accountId, maskedPhone);

        // B2.
        CustomerClient.CustomerProfile profile;
        try {
            profile = customerClient.createCustomer(req.fullName(), req.phone(), req.email(), req.dateOfBirth());
        } catch (RuntimeException e) {
            tx.executeWithoutResult(status -> users.deleteById(accountId));   // bù trừ
            log.warn("Registration step 2/3 failed, pending account id={} removed", accountId);
            throw e;
        }

        // B3.
        try {
            UUID publicId = tx.execute(status -> activate(accountId, profile.id(), client));
            log.info("Registration done: user={} customerId={}", publicId, profile.id());
            return new RegisterResponse(publicId, profile.id(), profile.customerCode());
        } catch (RuntimeException e) {
            // Hiếm (DB identity sập đúng lúc này). Hồ sơ khách đã tạo nhưng tài khoản còn PENDING:
            // ghi ERROR để vận hành đối soát bằng tay (hoặc job đối soát định kỳ).
            log.error("Registration step 3/3 failed: account id={} customerId={} NEEDS RECONCILIATION",
                    accountId, profile.id(), e);
            throw e;
        }
    }

    private Long createPendingAccount(RegisterRequest req) {
        if (users.existsByPhone(req.phone())) {
            throw new BusinessException(IdentityErrorCode.PHONE_ALREADY_REGISTERED);
        }
        try {
            UserAccount pending = UserAccount.newPendingCustomer(req.phone(),
                    passwordEncoder.encode(req.password()), clock.instant());
            return users.saveAndFlush(pending).getId();
        } catch (DataIntegrityViolationException e) {
            // Hai request cùng SĐT đến cùng lúc: cả hai qua được existsByPhone, UNIQUE ở DB chặn request thứ hai
            throw new BusinessException(IdentityErrorCode.PHONE_ALREADY_REGISTERED);
        }
    }

    private UUID activate(Long accountId, Long customerId, ClientInfo client) {
        UserAccount account = users.findByIdForUpdate(accountId).orElseThrow();
        Role customerRole = roles.findByCode(Role.CUSTOMER).orElseThrow();
        account.activateCustomer(customerId, customerRole);
        events.record(AuthEventType.USER_REGISTERED, account, client, null);
        return account.getPublicId();
    }
}
