# flower-shop-identity-service

Đăng nhập và phân quyền cho cả hệ thống: tài khoản nhân viên + khách hàng, cấp JWT, refresh token, RBAC, nhật ký bảo mật. PostgreSQL + Flyway.

Cổng local: `8083`

## Bức tranh tổng thể

```
Client ──login──► Gateway :8080 ──► identity-service :8083 ── identity_db
   │                                     │  ký JWT bằng PRIVATE key (RS256)
   │◄── accessToken (JWT, 15 phút) + refreshToken (chuỗi ngẫu nhiên, 7 ngày)
   │                                     └─ GET /.well-known/jwks.json  (PUBLIC key, có kid)
   │
   └─ Authorization: Bearer <JWT> ─► Gateway   lớp 1: chữ ký, hạn, iss, aud
                                       └─► catalog / customer   lớp 2: tự kiểm tra lại JWT + permission
identity ──(token riêng của service)──► customer-service   (lúc khách tự đăng ký)
```

Service khác **không gọi identity-service mỗi request**: chúng tải public key một lần từ JWKS rồi tự kiểm tra chữ ký.
Identity sập thì người đang đăng nhập vẫn dùng được hệ thống cho tới khi access token hết hạn.

## Các khái niệm chính

| Khái niệm | Ở đây làm thế nào | Vì sao |
|---|---|---|
| **Access token** | JWT ký RS256, sống 15 phút, mang `sub`, `user_type`, `roles`, `perms`, `customer_id` | Stateless: service tự kiểm tra, không hỏi DB. Đổi lại KHÔNG thu hồi được, nên phải ngắn hạn |
| **RS256 (khóa bất đối xứng)** | Chỉ identity giữ private key; ai cũng xem được public key | Service khác kiểm tra được chữ ký nhưng không tự tạo được token giả. HS256 (khóa chung) thì service nào giữ khóa cũng giả được token |
| **kid + JWKS** | Header JWT ghi `kid`; JWKS có thể chứa nhiều key | Xoay khóa không làm rớt phiên: token cũ vẫn kiểm tra được bằng key cũ còn trong JWKS |
| **Refresh token** | Chuỗi 256 bit ngẫu nhiên, DB chỉ lưu SHA-256 | Thu hồi được ngay (đăng xuất, khóa tài khoản). Lộ DB cũng không dùng được hash |
| **Rotation + phát hiện dùng lại** | Mỗi lần `/refresh` cấp token mới, token cũ bị đánh dấu `ROTATED`. Token `ROTATED` bị đem dùng lại → thu hồi cả **family** | Kẻ trộm và chủ thật không thể cùng dùng một token: ai dùng sau sẽ làm lộ vụ trộm, cả hai bị buộc đăng nhập lại |
| **RBAC 3 tầng** | user → role → permission (`resource:action`) | Code chỉ kiểm tra permission. Đổi "role nào làm được gì" là sửa dữ liệu, không sửa code |
| **Zero trust** | Gateway kiểm tra token, service vẫn kiểm tra lại | Gọi thẳng vào cổng service (bỏ qua gateway) vẫn bị chặn |
| **API `/me`** | Khách dùng `/api/v1/customers/me`, id lấy từ token | Không bao giờ tin id do client gửi lên cho dữ liệu "của tôi" |

## Role và permission mặc định (`V2__seed_roles_permissions.sql`)

| Role | Permission |
|---|---|
| `ADMIN` | tất cả |
| `SHOP_MANAGER` | `flower:write`, `customer:read`, `customer:create`, `customer:write`, `customer:deactivate`, `user:read` |
| `SHOP_STAFF` | `customer:read`, `customer:create`, `customer:write` |
| `CUSTOMER` | không có permission quản trị; chỉ dùng API `/me` |

Thêm permission/role: viết migration mới `V3__...sql`, rồi dùng `@PreAuthorize("hasAuthority('...')")` ở service cần.

## Luật bảo mật đã áp dụng

| Luật | Ở đâu |
|---|---|
| Sai username hay sai mật khẩu đều trả **cùng** `IDN-401-001`, user không tồn tại vẫn chạy bcrypt với hash giả (thời gian phản hồi như nhau) | `AuthService.doLogin`, `dummyHash` |
| Sai 5 lần → khóa 15 phút (`IDN-423-001`); đang khóa thì không kiểm tra mật khẩu | `UserAccount.recordFailedLogin` |
| Đếm sai mật khẩu bằng `SELECT ... FOR UPDATE` (hai request song song không làm mất một lần đếm) | `UserAccountRepository.findBy...ForUpdate` |
| **Bẫy transaction:** ném exception khi sai mật khẩu sẽ rollback luôn bộ đếm. Ở đây transaction trả kết quả, commit xong mới ném lỗi | `AuthService.Outcome`, `TransactionTemplate` |
| Mật khẩu bcrypt cost 12, lưu `{bcrypt}...` để sau đổi thuật toán không phải reset; tự băm lại khi cost tăng | `AppConfig.passwordEncoder`, `upgradeEncoding` |
| Mật khẩu ≥ 8 ký tự, có chữ + số, không chứa tên đăng nhập, ≤ 72 byte (giới hạn của bcrypt) | `PasswordPolicy` |
| Nhân viên mới / được reset mật khẩu phải đổi mật khẩu trước: token lúc đó **không có permission nào** | `TokenService.issueAccessToken` |
| Đổi mật khẩu, vô hiệu hóa, đổi role, reset mật khẩu → thu hồi mọi refresh token | `RefreshTokenService.revokeAllOfUser` |
| Không tự đổi role/trạng thái của chính mình; chỉ ADMIN mới đụng tới ADMIN | `UserAdminService.findForManage` |
| Response chứa token có `Cache-Control: no-store` | `AuthController.noStore` |
| `sub` là UUID công khai, không lộ id tuần tự | cột `public_id` |
| Nhật ký `auth_event` chỉ thêm (Hibernate `@Immutable`), ghi IP, User-Agent, correlation id | `AuthEventRecorder` |
| IP thật lấy phần tử **cuối** của `X-Forwarded-For` (phần gateway thêm vào; phần đầu client giả được) | `ClientInfo.from` |
| Thiếu private key ở môi trường thật → không khởi động (fail fast). Chỉ profile `local` tự sinh khóa | `JwtKeyService` |

## Đăng ký khách hàng: saga 3 bước

Tài khoản nằm ở `identity_db`, hồ sơ nằm ở `customer_db`, không transaction nào bao được cả hai:

1. identity: tạo tài khoản `PENDING` (UNIQUE phone chặn hai người đăng ký cùng SĐT)
2. gọi `POST /api/v1/customers` của customer-service bằng **token của chính identity-service** (`user_type=SERVICE`, chỉ có `customer:create`) — lỗi thì **bù trừ**: xóa tài khoản PENDING
3. identity: gắn `customer_id`, chuyển `ACTIVE`, gán role `CUSTOMER`

Giới hạn đã biết (học tiếp ở giai đoạn sau): bước 2 hết thời gian chờ nhưng thực ra đã tạo hồ sơ → hồ sơ mồ côi. Cách chữa: Idempotency-Key, outbox + Kafka. Chưa có OTP nên SĐT đã có hồ sơ (do nhân viên tạo) sẽ bị từ chối `IDN-409-003` thay vì tự gắn vào.

## Service token (client_credentials)

Service khác (vd order-service) muốn gọi API cần quyền thì xin token bằng client id + secret:

```
POST /internal/v1/service-token  {"clientId":"order-service","clientSecret":"..."}
→ {"tokenType":"Bearer","accessToken":"...","expiresIn":300}     (không có refresh token)
```

- Token có `sub` = client id, `user_type=SERVICE`, `perms` = đúng các permission cấp cho client (bảng `service_client_permission`).
- `/internal/**` **không đi qua gateway**: không có route, và gateway `denyAll()` kể cả khi có token. Chỉ gọi được trong mạng nội bộ.
- Sai client id / sai secret / client bị vô hiệu hóa: cùng mã `IDN-401-003`; mọi lần xin (được hay bị từ chối) ghi vào `auth_event`.
- Phía service gọi dùng `ServiceTokenClient` của common-lib: tự cache, xin lại trước khi hết hạn 1 phút, nhiều thread chỉ xin một lần.
- identity-service vẫn tự ký token cho chính nó (`ServiceTokenProvider`) vì nó là bên phát hành token.

Tạo client bằng cấu hình (lúc khởi động; đã có thì bỏ qua, cấu hình sai thì không khởi động):

```yaml
identity:
  service-clients:
    - client-id: order-service
      secret: ${ORDER_SERVICE_CLIENT_SECRET}    # >= 32 ký tự, tạo: openssl rand -base64 36
      permissions: [customer:read]
```

## API

| Method | Path | Quyền |
|---|---|---|
| POST | `/api/v1/auth/login` `{loginId, password}` | public. `loginId` = username (nhân viên) hoặc SĐT (khách) |
| POST | `/api/v1/auth/refresh` `{refreshToken}` | public |
| POST | `/api/v1/auth/logout` `{refreshToken}` | public, luôn trả thành công |
| POST | `/api/v1/auth/register` `{phone, password, fullName, email, dateOfBirth}` | public |
| GET | `/api/v1/auth/me` | đã đăng nhập |
| POST | `/api/v1/auth/change-password` `{currentPassword, newPassword}` | đã đăng nhập |
| GET | `/api/v1/users?type=STAFF\|CUSTOMER` · `/api/v1/users/{publicId}` | `user:read` |
| POST | `/api/v1/users` `{username, roles}` → trả mật khẩu tạm **một lần** | `user:write` |
| POST | `/api/v1/users/{publicId}/disable` · `enable` · `unlock` · `reset-password` | `user:write` |
| PUT | `/api/v1/users/{publicId}/roles` `{roles}` | `role:assign` |
| GET | `/api/v1/roles` | `role:read` |
| GET | `/.well-known/jwks.json` | public |
| POST | `/internal/v1/service-token` `{clientId, clientSecret}` | client id + secret, chỉ mạng nội bộ |

Mã lỗi: `IDN-400-001` mật khẩu yếu · `IDN-400-002` sai mật khẩu hiện tại · `IDN-400-003` role không hợp lệ · `IDN-401-001` sai thông tin đăng nhập · `IDN-401-002` refresh token không hợp lệ · `IDN-401-003` sai thông tin service client · `IDN-403-001` tài khoản bị vô hiệu hóa · `IDN-403-002` không tự sửa chính mình · `IDN-403-003` cần ADMIN · `IDN-404-001` không thấy tài khoản · `IDN-409-001` trùng username · `IDN-409-002` SĐT đã có tài khoản · `IDN-409-003` SĐT đã có hồ sơ · `IDN-409-004` trùng email · `IDN-422-001` chỉ gán role cho nhân viên · `IDN-423-001` tạm khóa · `IDN-503-001` customer-service không phản hồi.

Lỗi chung từ common-lib: `COM-401-001` thiếu/sai token · `COM-403-001` thiếu quyền.

## Cấu hình

| Biến môi trường | Ý nghĩa |
|---|---|
| `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` | Kết nối `identity_db` |
| `JWT_PRIVATE_KEY` | Private key RSA, PEM PKCS#8. Tạo: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` |
| `JWT_KEY_ID` | `kid` của khóa đang ký, ví dụ `2026-11` |
| `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD` | ADMIN đầu tiên, chỉ tạo khi hệ thống chưa có ADMIN nào |

Profile `local`: tự sinh khóa RSA mỗi lần khởi động (restart là token cũ mất hiệu lực, cần đăng nhập lại) và tạo ADMIN `admin` / `FlowerShop2026` (bị buộc đổi mật khẩu ở lần đăng nhập đầu).

**Xoay khóa:** tạo khóa mới, đặt vào `JWT_PRIVATE_KEY` + `JWT_KEY_ID` mới, đưa public key của khóa cũ vào
`identity.jwt.retired-public-keys.<kid cũ>`. Sau ít nhất 15 phút (TTL của access token) thì bỏ khóa cũ ra.

## Chạy

Cách khuyên dùng: chạy cả hệ thống từ repo `flower-shop-workspace` (`./clone-all.sh` rồi `./run-local.sh`).

Cần database `identity_db` (file `infra/postgres/init/03-create-identity-db.sql` trong workspace).

```bash
mvn verify     # cần Docker: test chạy với Postgres thật (Testcontainers)
```

## Release và Docker image

Merge PR `dev → production` thì GitHub Actions publish image `ghcr.io/flower-shop-teddy/flower-shop-identity-service:X.Y.Z` và tạo tag `vX.Y.Z`.
Chi tiết quy trình: README của repo `flower-shop-workspace`, mục "CI/CD và release".
