-- Quy tắc Flyway: file migration đã chạy thì KHÔNG BAO GIỜ sửa. Muốn đổi thì tạo V3__..., V4__...
--
-- Mô hình RBAC 3 tầng:  user_account --< user_role >-- role --< role_permission >-- permission
-- Code của các service chỉ kiểm tra PERMISSION (vd flower:write), không kiểm tra role.
-- Muốn đổi "role nào được làm gì" chỉ cần sửa dữ liệu, không phải sửa code service.

CREATE TABLE user_account (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Id công khai, dùng làm claim sub trong JWT. Không lộ id tuần tự ra ngoài (chống đoán/đếm số user).
    public_id            UUID         NOT NULL,
    user_type            VARCHAR(20)  NOT NULL,
    username             VARCHAR(50),             -- nhân viên đăng nhập bằng username
    phone                VARCHAR(10),             -- khách đăng nhập bằng SĐT
    -- Id hồ sơ bên customer-service. Không có FOREIGN KEY vì nằm ở DATABASE KHÁC (mỗi service một DB).
    customer_id          BIGINT,
    -- Có tiền tố thuật toán, vd {bcrypt}$2a$12$...: sau này đổi thuật toán không phải reset mật khẩu mọi người
    password_hash        VARCHAR(255) NOT NULL,
    status               VARCHAR(20)  NOT NULL,
    failed_login_count   INT          NOT NULL DEFAULT 0,
    locked_until         TIMESTAMPTZ,             -- khóa tạm do sai mật khẩu nhiều lần, hết hạn tự mở
    must_change_password BOOLEAN      NOT NULL DEFAULT FALSE,
    password_changed_at  TIMESTAMPTZ  NOT NULL,
    last_login_at        TIMESTAMPTZ,
    version              BIGINT       NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ  NOT NULL,
    created_by           VARCHAR(100) NOT NULL,
    updated_at           TIMESTAMPTZ,
    updated_by           VARCHAR(100),

    CONSTRAINT uk_user_public_id   UNIQUE (public_id),
    CONSTRAINT uk_user_username    UNIQUE (username),
    CONSTRAINT uk_user_phone       UNIQUE (phone),
    CONSTRAINT uk_user_customer_id UNIQUE (customer_id),
    CONSTRAINT ck_user_type        CHECK (user_type IN ('STAFF', 'CUSTOMER')),
    CONSTRAINT ck_user_status      CHECK (status IN ('PENDING', 'ACTIVE', 'DISABLED')),
    CONSTRAINT ck_user_username_format CHECK (username ~ '^[a-z][a-z0-9._]{2,49}$'),
    CONSTRAINT ck_user_phone_format    CHECK (phone ~ '^0[0-9]{9}$'),
    CONSTRAINT ck_user_failed_count    CHECK (failed_login_count >= 0),
    -- Nhân viên: có username, không có SĐT/hồ sơ khách. Khách: có SĐT, không có username.
    CONSTRAINT ck_user_staff_identity    CHECK (user_type <> 'STAFF'
                                                OR (username IS NOT NULL AND phone IS NULL AND customer_id IS NULL)),
    CONSTRAINT ck_user_customer_identity CHECK (user_type <> 'CUSTOMER' OR (phone IS NOT NULL AND username IS NULL)),
    -- Khách đã kích hoạt bắt buộc gắn với một hồ sơ khách hàng
    CONSTRAINT ck_user_customer_profile  CHECK (user_type <> 'CUSTOMER' OR status = 'PENDING' OR customer_id IS NOT NULL)
);

CREATE INDEX idx_user_type_created_at ON user_account (user_type, created_at DESC);

CREATE TABLE role (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code        VARCHAR(50)  NOT NULL,
    name        VARCHAR(100) NOT NULL,
    is_system   BOOLEAN      NOT NULL DEFAULT FALSE,   -- role có sẵn, không được xóa
    CONSTRAINT uk_role_code UNIQUE (code),
    CONSTRAINT ck_role_code_format CHECK (code ~ '^[A-Z][A-Z_]{1,49}$')
);

CREATE TABLE permission (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code        VARCHAR(100) NOT NULL,
    description VARCHAR(255) NOT NULL,
    CONSTRAINT uk_permission_code UNIQUE (code),
    CONSTRAINT ck_permission_code_format CHECK (code ~ '^[a-z][a-z-]*:[a-z][a-z-]*$')   -- resource:action
);

CREATE TABLE role_permission (
    role_id       BIGINT NOT NULL REFERENCES role (id),
    permission_id BIGINT NOT NULL REFERENCES permission (id),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_role (
    user_id    BIGINT      NOT NULL REFERENCES user_account (id),
    role_id    BIGINT      NOT NULL REFERENCES role (id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_role_role ON user_role (role_id);

-- Refresh token: DB chỉ lưu SHA-256 của token, không lưu token gốc.
-- Lộ DB cũng không dùng được các hash này để gọi /refresh.
-- family_id: mọi token sinh ra từ cùng MỘT lần đăng nhập. Phát hiện dùng lại token cũ -> thu hồi cả family.
CREATE TABLE refresh_token (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        BIGINT       NOT NULL REFERENCES user_account (id),
    token_hash     VARCHAR(64)  NOT NULL,
    family_id      UUID         NOT NULL,
    issued_at      TIMESTAMPTZ  NOT NULL,
    expires_at     TIMESTAMPTZ  NOT NULL,
    revoked_at     TIMESTAMPTZ,
    revoke_reason  VARCHAR(30),
    replaced_by_id BIGINT REFERENCES refresh_token (id),
    client_ip      VARCHAR(45),
    user_agent     VARCHAR(255),
    CONSTRAINT uk_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT ck_refresh_token_hash_format CHECK (token_hash ~ '^[0-9a-f]{64}$'),   -- SHA-256 dạng hex
    CONSTRAINT ck_refresh_token_revoke CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);

CREATE INDEX idx_refresh_token_family ON refresh_token (family_id);
CREATE INDEX idx_refresh_token_user_active ON refresh_token (user_id) WHERE revoked_at IS NULL;

-- Nhật ký bảo mật: CHỈ THÊM, không sửa, không xóa (ứng dụng không có code update/delete bảng này).
-- Trả lời được: ai đăng nhập lúc nào, từ IP nào, ai đã đổi quyền của ai.
CREATE TABLE auth_event (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_type      VARCHAR(40)  NOT NULL,
    user_id         BIGINT,                  -- NULL khi đăng nhập bằng tài khoản không tồn tại
    login_id_masked VARCHAR(60),
    actor           VARCHAR(100),            -- người thực hiện (sub), khác user_id khi admin thao tác trên user khác
    detail          VARCHAR(255),
    client_ip       VARCHAR(45),
    user_agent      VARCHAR(255),
    correlation_id  VARCHAR(64),
    occurred_at     TIMESTAMPTZ  NOT NULL
);

CREATE INDEX idx_auth_event_user_time ON auth_event (user_id, occurred_at DESC);
CREATE INDEX idx_auth_event_type_time ON auth_event (event_type, occurred_at DESC);
