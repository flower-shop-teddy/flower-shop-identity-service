-- Permission cho order-service (API của nhân viên).
-- Khách KHÔNG cần permission nào: API /api/v1/orders/me chỉ cho khách thao tác trên đơn của chính mình (id từ token).

INSERT INTO permission (code, description) VALUES
    ('order:read',   'Xem đơn hàng và lịch sử trạng thái'),
    ('order:manage', 'Xác nhận, chuyển trạng thái, hủy đơn hàng');

INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r JOIN permission p ON p.code IN ('order:read', 'order:manage')
WHERE r.code IN ('ADMIN', 'SHOP_MANAGER', 'SHOP_STAFF');
