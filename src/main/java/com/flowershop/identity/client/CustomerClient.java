package com.flowershop.identity.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flowershop.common.error.BusinessException;
import com.flowershop.common.web.CorrelationId;
import com.flowershop.identity.config.IdentityProperties;
import com.flowershop.identity.error.IdentityErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Gọi customer-service qua Eureka (base-url http://customer-service, @LoadBalanced tự đổi thành IP:port).
 * - Luôn đặt TIMEOUT: không có timeout thì customer-service treo là identity-service treo theo.
 * - Truyền X-Correlation-Id để log hai service nối được với nhau.
 * - Gửi Bearer token của chính identity-service (zero trust: customer-service không tin ai không có token).
 */
@Slf4j
@Component
public class CustomerClient {

    public record CustomerProfile(Long id, String customerCode) {
    }

    private final RestClient restClient;
    private final ServiceTokenProvider serviceToken;
    private final ObjectMapper objectMapper;

    public CustomerClient(RestClient.Builder loadBalancedBuilder, IdentityProperties props,
                          ServiceTokenProvider serviceToken, ObjectMapper objectMapper) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(props.customerService().connectTimeout());
        factory.setReadTimeout(props.customerService().readTimeout());
        this.restClient = loadBalancedBuilder.clone()
                .baseUrl(props.customerService().baseUrl())
                .requestFactory(factory)
                .build();
        this.serviceToken = serviceToken;
        this.objectMapper = objectMapper;
    }

    public CustomerProfile createCustomer(String fullName, String phone, String email, LocalDate dateOfBirth) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("fullName", fullName);
        body.put("phone", phone);
        body.put("email", email);
        body.put("dateOfBirth", dateOfBirth == null ? null : dateOfBirth.toString());   // ISO yyyy-MM-dd
        try {
            JsonNode response = restClient.post()
                    .uri("/api/v1/customers")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken.get())
                    .headers(h -> {
                        String correlationId = MDC.get(CorrelationId.MDC_KEY);
                        if (correlationId != null) {
                            h.set(CorrelationId.HEADER, correlationId);
                        }
                    })
                    .body(body)
                    .retrieve()
                    .body(JsonNode.class);
            JsonNode data = response == null ? null : response.path("data");
            if (data == null || !data.hasNonNull("id")) {
                throw new BusinessException(IdentityErrorCode.CUSTOMER_SERVICE_UNAVAILABLE);
            }
            return new CustomerProfile(data.get("id").asLong(), data.path("customerCode").asText(null));
        } catch (RestClientResponseException e) {
            throw translate(e);
        } catch (RestClientException e) {
            // Không kết nối được, hết thời gian chờ, không tìm thấy instance trên Eureka...
            log.error("Call customer-service failed: {}", e.getClass().getSimpleName(), e);
            throw new BusinessException(IdentityErrorCode.CUSTOMER_SERVICE_UNAVAILABLE);
        }
    }

    /** Đổi mã lỗi của customer-service thành mã lỗi của identity: client không cần biết bên trong có mấy service. */
    private BusinessException translate(RestClientResponseException e) {
        String code = null;
        try {
            code = objectMapper.readTree(e.getResponseBodyAsString()).path("code").asText(null);
        } catch (Exception ignored) {
            // body không phải JSON
        }
        log.warn("customer-service responded {} code={}", e.getStatusCode().value(), code);
        if ("CUS-409-001".equals(code)) {
            return new BusinessException(IdentityErrorCode.CUSTOMER_PROFILE_EXISTS);
        }
        if ("CUS-409-002".equals(code)) {
            return new BusinessException(IdentityErrorCode.EMAIL_ALREADY_USED);
        }
        return new BusinessException(IdentityErrorCode.CUSTOMER_SERVICE_UNAVAILABLE);
    }
}
