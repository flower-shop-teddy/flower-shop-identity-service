package com.flowershop.identity;

import com.flowershop.common.error.BusinessException;
import com.flowershop.identity.client.CustomerClient;
import com.flowershop.identity.domain.AuthEventType;
import com.flowershop.identity.error.IdentityErrorCode;
import com.flowershop.identity.repository.AuthEventRepository;
import com.flowershop.identity.repository.ServiceClientRepository;
import com.flowershop.identity.repository.UserAccountRepository;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Test tích hợp với Postgres thật (Testcontainers). Cần Docker đang chạy.
 * customer-service được thay bằng mock (CustomerClient) để test luồng đăng ký mà không cần bật service đó.
 */
@SpringBootTest(properties = {
        "DB_URL=jdbc:postgresql://unused:5432/unused",
        "DB_USERNAME=unused",
        "DB_PASSWORD=unused",
        "eureka.client.enabled=false",
        "identity.jwt.generate-dev-key=true",
        "identity.password.bcrypt-strength=4",       // test nhanh; production dùng 12
        "identity.bootstrap-admin.username=admin",
        "identity.bootstrap-admin.password=FlowerShop2026",
        "identity.service-clients[0].client-id=order-service",
        "identity.service-clients[0].secret=" + IdentityApiIntegrationTest.ORDER_SECRET,
        "identity.service-clients[0].permissions=customer:read,inventory:reserve",
        "identity.service-clients[1].client-id=retired-service",
        "identity.service-clients[1].secret=" + IdentityApiIntegrationTest.RETIRED_SECRET,
        "identity.service-clients[1].permissions=customer:read"
})
@AutoConfigureMockMvc
@Testcontainers
class IdentityApiIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    static final String ORDER_SECRET = "order-secret-for-test-only-0123456789";
    static final String RETIRED_SECRET = "retired-secret-for-test-only-0123456789";

    private static final AtomicInteger SEQ = new AtomicInteger();
    private static final String ADMIN_NEW_PASSWORD = "QuanTri2026x";
    private static String adminToken;

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AuthEventRepository authEvents;

    @Autowired
    UserAccountRepository users;

    @Autowired
    ServiceClientRepository serviceClients;

    @MockitoBean
    CustomerClient customerClient;

    // ---------------------------------------------------------------- JWKS

    @Test
    void jwks_publishesOnlyPublicKey() throws Exception {
        String body = mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "max-age=300, public"))
                .andReturn().getResponse().getContentAsString();
        RSAKey key = JWKSet.parse(body).getKeys().getFirst().toRSAKey();
        assertThat(key.isPrivate()).isFalse();
        assertThat(key.getKeyID()).isNotBlank();
    }

    @Test
    void accessToken_isVerifiableWithJwks_andCarriesClaims() throws Exception {
        String token = adminToken();
        String jwks = mockMvc.perform(get("/.well-known/jwks.json")).andReturn().getResponse().getContentAsString();
        RSAKey key = JWKSet.parse(jwks).getKeys().getFirst().toRSAKey();

        // Cách mọi service khác kiểm tra token: chỉ cần public key, không cần gọi identity-service
        Jwt jwt = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build().decode(token);
        assertThat(jwt.getClaimAsString("iss")).isEqualTo("flower-shop-identity");
        assertThat(jwt.getAudience()).containsExactly("flower-shop-api");
        assertThat(jwt.getHeaders()).containsEntry("kid", key.getKeyID());
        assertThat(jwt.getClaimAsString("user_type")).isEqualTo("STAFF");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("ADMIN");
        assertThat(jwt.getClaimAsStringList("perms")).contains("user:write", "flower:write", "inventory:write")
                .doesNotContain("inventory:reserve");   // chỉ service client mới giữ hàng được
        assertThat(UUID.fromString(jwt.getSubject())).isNotNull();
    }

    // ---------------------------------------------------------------- Login

    @Test
    void login_unknownUser_andWrongPassword_returnSameError() throws Exception {
        login("khong-ton-tai", "Whatever123")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("IDN-401-001"));

        String username = createStaff("SHOP_STAFF").username;
        login(username, "SaiMatKhau1")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("IDN-401-001"))
                .andExpect(jsonPath("$.message").value("Thông tin đăng nhập không đúng"));
    }

    @Test
    void newStaff_mustChangePasswordFirst_tokenHasNoPermissions() throws Exception {
        Staff staff = createStaff("SHOP_MANAGER");

        String body = login(staff.username, staff.password)
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.data.passwordChangeRequired").value(true))
                .andReturn().getResponse().getContentAsString();
        String limitedToken = JsonPath.read(body, "$.data.accessToken");

        // Token "hạn chế": không có permission nào -> API quản trị trả 403
        mockMvc.perform(get("/api/v1/users").header("Authorization", bearer(limitedToken)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("COM-403-001"));

        changePassword(limitedToken, staff.password, "Manager123")
                .andExpect(status().isOk());

        String fullToken = accessToken(login(staff.username, "Manager123"));
        mockMvc.perform(get("/api/v1/users").header("Authorization", bearer(fullToken)))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", bearer(fullToken)))
                .andExpect(jsonPath("$.data.roles[0]").value("SHOP_MANAGER"))
                .andExpect(jsonPath("$.data.permissions").value(org.hamcrest.Matchers.hasItem("flower:write")));
    }

    @Test
    void fiveWrongPasswords_lockAccount_andFailuresAreNotRolledBack() throws Exception {
        Staff staff = createStaff("SHOP_STAFF");

        for (int i = 1; i <= 4; i++) {
            login(staff.username, "SaiMatKhau" + i).andExpect(jsonPath("$.code").value("IDN-401-001"));
        }
        login(staff.username, "SaiMatKhau5")
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.code").value("IDN-423-001"));
        // Đang khóa thì mật khẩu ĐÚNG cũng bị từ chối
        login(staff.username, staff.password).andExpect(status().isLocked());

        // Bằng chứng không bị rollback: nhật ký thất bại đã nằm trong DB
        Long userId = users.findByPublicId(staff.publicId).orElseThrow().getId();
        assertThat(authEvents.findByUserIdAndEventTypeOrderByIdDesc(userId, AuthEventType.LOGIN_FAILED))
                .hasSizeGreaterThanOrEqualTo(6);
        assertThat(authEvents.findByUserIdAndEventTypeOrderByIdDesc(userId, AuthEventType.ACCOUNT_LOCKED))
                .hasSize(1);

        mockMvc.perform(post("/api/v1/users/{id}/unlock", staff.publicId).header("Authorization", bearer(adminToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.locked").value(false));
        login(staff.username, staff.password).andExpect(status().isOk());
    }

    @Test
    void disabledAccount_cannotLogin_andLosesRefreshTokens() throws Exception {
        Staff staff = createStaff("SHOP_STAFF");
        String refresh = refreshToken(login(staff.username, staff.password));

        mockMvc.perform(post("/api/v1/users/{id}/disable", staff.publicId).header("Authorization", bearer(adminToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("DISABLED"));

        login(staff.username, staff.password)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IDN-403-001"));
        refresh(refresh).andExpect(jsonPath("$.code").value("IDN-401-002"));
    }

    // ---------------------------------------------------------------- Refresh token

    @Test
    void refresh_rotates_andReuseOfOldTokenRevokesWholeFamily() throws Exception {
        Staff staff = createStaff("SHOP_STAFF");
        String r1 = refreshToken(login(staff.username, staff.password));

        String r2 = refreshToken(refresh(r1).andExpect(status().isOk()));
        assertThat(r2).isNotEqualTo(r1);

        // Kẻ trộm (hoặc chủ thật) dùng lại r1 đã bị thay -> từ chối, và thu hồi luôn r2
        refresh(r1).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("IDN-401-002"));
        refresh(r2).andExpect(status().isUnauthorized());

        Long userId = users.findByPublicId(staff.publicId).orElseThrow().getId();
        assertThat(authEvents.findByUserIdAndEventTypeOrderByIdDesc(userId, AuthEventType.TOKEN_REUSE_DETECTED))
                .hasSize(1);
    }

    @Test
    void logout_revokesRefreshToken() throws Exception {
        Staff staff = createStaff("SHOP_STAFF");
        String r1 = refreshToken(login(staff.username, staff.password));

        mockMvc.perform(post("/api/v1/auth/logout").contentType(APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + r1 + "\"}"))
                .andExpect(status().isOk());
        refresh(r1).andExpect(status().isUnauthorized());

        // Token rác vẫn trả thành công: không lộ token nào có thật
        mockMvc.perform(post("/api/v1/auth/logout").contentType(APPLICATION_JSON)
                        .content("{\"refreshToken\":\"abc\"}"))
                .andExpect(status().isOk());
    }

    // ---------------------------------------------------------------- Phân quyền

    @Test
    void noToken_returns401_withStandardBody() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"))
                .andExpect(jsonPath("$.code").value("COM-401-001"))
                .andExpect(header().exists("X-Correlation-Id"));

        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer khong-phai-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("COM-401-001"));
    }

    @Test
    void staffWithoutPermission_getsForbidden() throws Exception {
        Staff staff = createStaff("SHOP_STAFF");
        String token = activatedToken(staff);
        mockMvc.perform(get("/api/v1/roles").header("Authorization", bearer(token)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("COM-403-001"));
    }

    @Test
    void admin_cannotChangeOwnRoles() throws Exception {
        String token = adminToken();
        String me = mockMvc.perform(get("/api/v1/auth/me").header("Authorization", bearer(token)))
                .andReturn().getResponse().getContentAsString();
        String publicId = JsonPath.read(me, "$.data.publicId");

        mockMvc.perform(put("/api/v1/users/{id}/roles", publicId).header("Authorization", bearer(token))
                        .contentType(APPLICATION_JSON).content("{\"roles\":[\"SHOP_STAFF\"]}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("IDN-403-002"));
    }

    @Test
    void assignRoles_changesPermissionsInNextToken() throws Exception {
        Staff staff = createStaff("SHOP_STAFF");
        String token = activatedToken(staff);

        mockMvc.perform(put("/api/v1/users/{id}/roles", staff.publicId).header("Authorization", bearer(adminToken()))
                        .contentType(APPLICATION_JSON).content("{\"roles\":[\"SHOP_MANAGER\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.roles[0]").value("SHOP_MANAGER"));

        // Token cũ vẫn mang quyền cũ (JWT stateless) cho tới khi hết hạn; token mới có quyền mới
        mockMvc.perform(get("/api/v1/users").header("Authorization", bearer(token)))
                .andExpect(status().isForbidden());
        String newToken = accessToken(login(staff.username, "Staff12345x"));
        mockMvc.perform(get("/api/v1/users").header("Authorization", bearer(newToken)))
                .andExpect(status().isOk());
    }

    @Test
    void customerRole_cannotBeAssignedToStaff() throws Exception {
        mockMvc.perform(post("/api/v1/users").header("Authorization", bearer(adminToken()))
                        .contentType(APPLICATION_JSON).content("{\"username\":\"nv.sai\",\"roles\":[\"CUSTOMER\"]}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("IDN-400-003"));
    }

    // ---------------------------------------------------------------- Đăng ký khách

    @Test
    void register_createsCustomerAccount_loginByPhone_tokenHasCustomerId() throws Exception {
        String phone = nextPhone();
        given(customerClient.createCustomer(anyString(), eq(phone), any(), any()))
                .willReturn(new CustomerClient.CustomerProfile(42L, "KH_CN_0000042"));

        register(phone, "KhachHang1")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.customerId").value(42))
                .andExpect(jsonPath("$.data.customerCode").value("KH_CN_0000042"));

        String token = accessToken(login(phone, "KhachHang1").andExpect(status().isOk()));
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", bearer(token)))
                .andExpect(jsonPath("$.data.userType").value("CUSTOMER"))
                .andExpect(jsonPath("$.data.customerId").value(42))
                .andExpect(jsonPath("$.data.roles[0]").value("CUSTOMER"))
                .andExpect(jsonPath("$.data.permissions").isEmpty());

        register(phone, "KhachHang1")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("IDN-409-002"));
    }

    @Test
    void register_whenCustomerServiceFails_pendingAccountIsCompensated() throws Exception {
        String phone = nextPhone();
        given(customerClient.createCustomer(anyString(), eq(phone), any(), any()))
                .willThrow(new BusinessException(IdentityErrorCode.CUSTOMER_SERVICE_UNAVAILABLE));

        register(phone, "KhachHang1")
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("IDN-503-001"));
        // Bước bù trừ đã xóa tài khoản PENDING: SĐT không bị "kẹt"
        assertThat(users.existsByPhone(phone)).isFalse();

        given(customerClient.createCustomer(anyString(), eq(phone), any(), any()))
                .willReturn(new CustomerClient.CustomerProfile(43L, "KH_CN_0000043"));
        register(phone, "KhachHang1").andExpect(status().isCreated());
    }

    @Test
    void register_weakPassword_returns400() throws Exception {
        String phone = nextPhone();
        register(phone, "12345678")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("IDN-400-001"));
        register(phone, "a" + phone)
                .andExpect(jsonPath("$.code").value("IDN-400-001"));
    }

    // ---------------------------------------------------------------- Service token (client_credentials)

    @Test
    void serviceToken_validClient_getsTokenWithOnlyGrantedPermissions() throws Exception {
        String body = serviceToken("order-service", ORDER_SECRET)
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.data.expiresIn").value(300))
                .andExpect(jsonPath("$.data.refreshToken").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        String jwks = mockMvc.perform(get("/.well-known/jwks.json")).andReturn().getResponse().getContentAsString();
        RSAKey key = JWKSet.parse(jwks).getKeys().getFirst().toRSAKey();
        Jwt jwt = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build()
                .decode(JsonPath.read(body, "$.data.accessToken"));
        assertThat(jwt.getSubject()).isEqualTo("order-service");
        assertThat(jwt.getClaimAsString("user_type")).isEqualTo("SERVICE");
        assertThat(jwt.getClaimAsStringList("perms")).containsExactly("customer:read", "inventory:reserve");
        assertThat(jwt.getClaimAsStringList("roles")).isEmpty();
        assertThat(serviceEvents(AuthEventType.SERVICE_TOKEN_ISSUED, "client=order-service")).isPositive();
    }

    @Test
    void serviceToken_wrongSecret_unknownClient_disabledClient_returnSameError() throws Exception {
        serviceClients.findByClientId("retired-service").ifPresent(c -> {
            c.disable();
            serviceClients.save(c);
        });

        for (String[] attempt : new String[][]{
                {"order-service", "sai-secret-sai-secret-sai-secret-0000"},
                {"khong-ton-tai", ORDER_SECRET},
                {"retired-service", RETIRED_SECRET}}) {
            serviceToken(attempt[0], attempt[1])
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code").value("IDN-401-003"))
                    .andExpect(jsonPath("$.message").value("Thông tin xác thực service không đúng"));
        }
        // Nhật ký vẫn còn dù request trả lỗi (không bị rollback), và ghi rõ lý do để điều tra
        assertThat(serviceEvents(AuthEventType.SERVICE_TOKEN_DENIED, "client=order-service BAD_SECRET")).isPositive();
        assertThat(serviceEvents(AuthEventType.SERVICE_TOKEN_DENIED, "client=khong-ton-tai UNKNOWN_CLIENT")).isPositive();
        assertThat(serviceEvents(AuthEventType.SERVICE_TOKEN_DENIED, "client=retired-service STATUS_DISABLED")).isPositive();
    }

    @Test
    void serviceToken_invalidClientIdFormat_isRejectedBeforeLookup() throws Exception {
        serviceToken("Order Service; DROP", ORDER_SECRET)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("COM-400-001"));
    }

    @Test
    void serviceToken_cannotBeUsedToCallUserApis_withoutPermission() throws Exception {
        String token = JsonPath.read(serviceToken("order-service", ORDER_SECRET).andReturn().getResponse()
                .getContentAsString(), "$.data.accessToken");
        mockMvc.perform(get("/api/v1/users").header("Authorization", bearer(token)))
                .andExpect(status().isForbidden());
    }

    // ---------------------------------------------------------------- helpers

    private record Staff(UUID publicId, String username, String password) {
    }

    private ResultActions login(String loginId, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/login").contentType(APPLICATION_JSON)
                .content("{\"loginId\":\"%s\",\"password\":\"%s\"}".formatted(loginId, password)));
    }

    private ResultActions refresh(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/refresh").contentType(APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + refreshToken + "\"}"));
    }

    private ResultActions changePassword(String token, String current, String next) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/change-password").header("Authorization", bearer(token))
                .contentType(APPLICATION_JSON)
                .content("{\"currentPassword\":\"%s\",\"newPassword\":\"%s\"}".formatted(current, next)));
    }

    private ResultActions serviceToken(String clientId, String secret) throws Exception {
        return mockMvc.perform(post("/internal/v1/service-token").contentType(APPLICATION_JSON)
                .content("{\"clientId\":\"%s\",\"clientSecret\":\"%s\"}".formatted(clientId, secret)));
    }

    private long serviceEvents(AuthEventType type, String detail) {
        return authEvents.findAll().stream()
                .filter(e -> e.getEventType() == type && detail.equals(e.getDetail()))
                .count();
    }

    private ResultActions register(String phone, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/register").contentType(APPLICATION_JSON).content("""
                {"phone":"%s","password":"%s","fullName":"Nguyễn Thị Lan","email":null,"dateOfBirth":"1995-03-20"}
                """.formatted(phone, password)));
    }

    private static String accessToken(ResultActions result) throws Exception {
        return JsonPath.read(result.andReturn().getResponse().getContentAsString(), "$.data.accessToken");
    }

    private static String refreshToken(ResultActions result) throws Exception {
        return JsonPath.read(result.andReturn().getResponse().getContentAsString(), "$.data.refreshToken");
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private static String nextPhone() {
        return "09%08d".formatted(SEQ.incrementAndGet());
    }

    /** ADMIN bootstrap phải đổi mật khẩu trước, làm một lần rồi dùng lại token. */
    private synchronized String adminToken() throws Exception {
        if (adminToken == null) {
            String first = login("admin", "FlowerShop2026").andReturn().getResponse().getContentAsString();
            if (JsonPath.<Boolean>read(first, "$.data.passwordChangeRequired") != null
                    && JsonPath.<Boolean>read(first, "$.data.passwordChangeRequired")) {
                changePassword(JsonPath.read(first, "$.data.accessToken"), "FlowerShop2026", ADMIN_NEW_PASSWORD)
                        .andExpect(status().isOk());
            }
            adminToken = accessToken(login("admin", ADMIN_NEW_PASSWORD).andExpect(status().isOk()));
        }
        return adminToken;
    }

    private Staff createStaff(String role) throws Exception {
        String username = "nv" + SEQ.incrementAndGet();
        String body = mockMvc.perform(post("/api/v1/users").header("Authorization", bearer(adminToken()))
                        .contentType(APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"roles\":[\"%s\"]}".formatted(username, role)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.user.passwordChangeRequired").value(true))
                .andReturn().getResponse().getContentAsString();
        return new Staff(UUID.fromString(JsonPath.read(body, "$.data.user.publicId")), username,
                JsonPath.read(body, "$.data.temporaryPassword"));
    }

    /** Đăng nhập lần đầu, đổi mật khẩu tạm thành Staff12345x, trả token đầy đủ quyền. */
    private String activatedToken(Staff staff) throws Exception {
        String limited = accessToken(login(staff.username, staff.password));
        changePassword(limited, staff.password, "Staff12345x").andExpect(status().isOk());
        return accessToken(login(staff.username, "Staff12345x"));
    }
}
