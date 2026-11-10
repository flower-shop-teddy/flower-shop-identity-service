package com.flowershop.identity.client;

import com.flowershop.common.api.ApiResponse;
import com.flowershop.common.client.RemoteServiceException;
import com.flowershop.common.client.ServiceClientFactory;
import com.flowershop.common.client.ServiceEndpoint;
import com.flowershop.common.error.BusinessException;
import com.flowershop.identity.config.IdentityProperties;
import com.flowershop.identity.error.IdentityErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.service.annotation.PostExchange;

import java.time.LocalDate;

/**
 * Gọi customer-service. Timeout, correlation id, Bearer token và đọc mã lỗi đều do
 * {@link ServiceClientFactory} (common-lib) lo; ở đây chỉ còn API và cách dịch mã lỗi.
 */
@Slf4j
@Component
public class CustomerClient {

    public record CustomerProfile(Long id, String customerCode) {
    }

    record CreateCustomerBody(String fullName, String phone, String email, LocalDate dateOfBirth) {
    }

    /**
     * KHÔNG đánh dấu @Idempotent: tạo hồ sơ không idempotent, timeout rồi gọi lại có thể tạo hai hồ sơ.
     * Lỗi thì saga đăng ký bù trừ (xóa tài khoản PENDING), khách đăng ký lại.
     */
    interface CustomerApi {
        @PostExchange("/api/v1/customers")
        ApiResponse<CustomerProfile> create(@RequestBody CreateCustomerBody body);
    }

    private final CustomerApi api;

    public CustomerClient(ServiceClientFactory clients, IdentityProperties props, ServiceTokenProvider serviceToken) {
        IdentityProperties.CustomerService cfg = props.customerService();
        ServiceEndpoint endpoint = new ServiceEndpoint("customer-service", cfg.baseUrl(),
                cfg.connectTimeout(), cfg.readTimeout());
        this.api = clients.create(CustomerApi.class, endpoint, serviceToken::get);
    }

    public CustomerProfile createCustomer(String fullName, String phone, String email, LocalDate dateOfBirth) {
        try {
            ApiResponse<CustomerProfile> response = api.create(new CreateCustomerBody(fullName, phone, email, dateOfBirth));
            CustomerProfile profile = response == null ? null : response.data();
            if (profile == null || profile.id() == null) {
                throw new BusinessException(IdentityErrorCode.CUSTOMER_SERVICE_UNAVAILABLE);
            }
            return profile;
        } catch (RemoteServiceException e) {
            throw translate(e);
        }
    }

    /** Đổi mã lỗi của customer-service thành mã lỗi của identity: client không cần biết bên trong có mấy service. */
    private BusinessException translate(RemoteServiceException e) {
        if (e.hasCode("CUS-409-001")) {
            return new BusinessException(IdentityErrorCode.CUSTOMER_PROFILE_EXISTS);
        }
        if (e.hasCode("CUS-409-002")) {
            return new BusinessException(IdentityErrorCode.EMAIL_ALREADY_USED);
        }
        log.error("Call customer-service failed: {}", e.getMessage(), e);
        return new BusinessException(IdentityErrorCode.CUSTOMER_SERVICE_UNAVAILABLE);
    }
}
