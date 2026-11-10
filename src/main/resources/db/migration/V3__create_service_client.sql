-- Service client: "tài khoản" của một SERVICE (vd order-service) để xin token gọi service khác.
-- Luồng client_credentials: service gửi client_id + secret -> nhận access token ngắn hạn chỉ mang đúng
-- các permission được cấp ở bảng service_client_permission (least privilege).
--
-- Không có dòng seed nào: secret khác nhau theo môi trường, tạo lúc khởi động từ cấu hình
-- identity.service-clients (xem ServiceClientBootstrap), giống cách tạo ADMIN đầu tiên.

CREATE TABLE service_client (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id   VARCHAR(50)  NOT NULL,
    -- Giống mật khẩu: chỉ lưu hash có tiền tố thuật toán ({bcrypt}$2a$...), không lưu secret gốc
    secret_hash VARCHAR(255) NOT NULL,
    status      VARCHAR(20)  NOT NULL,
    version     BIGINT       NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL,
    created_by  VARCHAR(100) NOT NULL,
    updated_at  TIMESTAMPTZ,
    updated_by  VARCHAR(100),

    CONSTRAINT uk_service_client_client_id UNIQUE (client_id),
    CONSTRAINT ck_service_client_id_format CHECK (client_id ~ '^[a-z][a-z0-9-]{2,49}$'),
    CONSTRAINT ck_service_client_status    CHECK (status IN ('ACTIVE', 'DISABLED'))
);

-- Dùng lại bảng permission của người dùng: service và người cùng một bộ quyền, service đích chỉ kiểm tra permission
CREATE TABLE service_client_permission (
    service_client_id BIGINT NOT NULL REFERENCES service_client (id),
    permission_id     BIGINT NOT NULL REFERENCES permission (id),
    PRIMARY KEY (service_client_id, permission_id)
);
