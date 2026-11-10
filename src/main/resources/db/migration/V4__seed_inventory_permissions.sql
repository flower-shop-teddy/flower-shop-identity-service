-- Permission cho inventory-service.
-- inventory:reserve KHÔNG gán cho role nào của người: chỉ service client (order-service) được giữ/nhả hàng,
-- nhân viên muốn giữ hàng thì tạo đơn qua order-service (một luồng duy nhất, đủ nhật ký).

INSERT INTO permission (code, description) VALUES
    ('inventory:read',    'Xem tồn kho, lô hàng, lịch sử nhập/xuất'),
    ('inventory:write',   'Nhập lô hàng mới, ghi nhận hoa hỏng/hủy'),
    ('inventory:reserve', 'Giữ, xác nhận, nhả hàng cho đơn (chỉ dành cho service)');

INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r JOIN permission p ON p.code IN ('inventory:read', 'inventory:write')
WHERE r.code IN ('ADMIN', 'SHOP_MANAGER', 'SHOP_STAFF');
