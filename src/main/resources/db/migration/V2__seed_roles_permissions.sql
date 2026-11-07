-- Dữ liệu gốc của phân quyền. Thêm permission/role mới thì viết migration mới (V3__...).

INSERT INTO permission (code, description) VALUES
    ('flower:write',        'Tạo, sửa, ngừng kinh doanh sản phẩm hoa'),
    ('customer:read',       'Xem hồ sơ và sổ địa chỉ của khách hàng'),
    ('customer:create',     'Tạo hồ sơ khách hàng'),
    ('customer:write',      'Sửa hồ sơ và sổ địa chỉ của khách hàng'),
    ('customer:deactivate', 'Ngừng hoạt động khách hàng'),
    ('user:read',           'Xem danh sách tài khoản'),
    ('user:write',          'Tạo tài khoản nhân viên, khóa/mở khóa, đặt lại mật khẩu'),
    ('role:read',           'Xem danh sách role và permission'),
    ('role:assign',         'Gán role cho tài khoản nhân viên');

INSERT INTO role (code, name, is_system) VALUES
    ('ADMIN',        'Quản trị hệ thống',  TRUE),
    ('SHOP_MANAGER', 'Quản lý cửa hàng',   TRUE),
    ('SHOP_STAFF',   'Nhân viên cửa hàng', TRUE),
    -- Khách hàng không có permission quản trị nào: chỉ dùng API /me (dữ liệu của chính mình)
    ('CUSTOMER',     'Khách hàng',         TRUE);

-- ADMIN: mọi permission
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r CROSS JOIN permission p WHERE r.code = 'ADMIN';

INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r JOIN permission p ON p.code IN (
    'flower:write', 'customer:read', 'customer:create', 'customer:write', 'customer:deactivate', 'user:read'
) WHERE r.code = 'SHOP_MANAGER';

INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r JOIN permission p ON p.code IN (
    'customer:read', 'customer:create', 'customer:write'
) WHERE r.code = 'SHOP_STAFF';
