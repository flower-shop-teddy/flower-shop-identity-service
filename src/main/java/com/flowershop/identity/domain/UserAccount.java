package com.flowershop.identity.domain;

import com.flowershop.common.security.UserType;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Tài khoản đăng nhập. CHỈ chứa thông tin để xác thực và phân quyền.
 * Họ tên, email, địa chỉ... là hồ sơ khách hàng, thuộc customer-service (mỗi service một nghiệp vụ).
 */
@Entity
@Table(name = "user_account")
@EntityListeners(AuditingEntityListener.class)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "public_id", nullable = false, unique = true, updatable = false)
    private UUID publicId;

    @Enumerated(EnumType.STRING)
    @Column(name = "user_type", nullable = false, length = 20, updatable = false)
    private UserType userType;

    @Column(length = 50, unique = true, updatable = false)
    private String username;

    @Column(length = 10, unique = true, updatable = false)
    private String phone;

    @Column(name = "customer_id", unique = true)
    private Long customerId;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private UserStatus status;

    @Column(name = "failed_login_count", nullable = false)
    private int failedLoginCount;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "must_change_password", nullable = false)
    private boolean mustChangePassword;

    @Column(name = "password_changed_at", nullable = false)
    private Instant passwordChangedAt;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @ManyToMany
    @JoinTable(name = "user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    @Version
    private Long version;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @CreatedBy
    @Column(name = "created_by", nullable = false, updatable = false, length = 100)
    private String createdBy;

    @LastModifiedDate
    @Column(name = "updated_at")
    private Instant updatedAt;

    @LastModifiedBy
    @Column(name = "updated_by", length = 100)
    private String updatedBy;

    /** Nhân viên mới luôn phải đổi mật khẩu ở lần đăng nhập đầu: mật khẩu tạm do người khác đặt. */
    public static UserAccount newStaff(String username, String passwordHash, Set<Role> roles, Instant now) {
        UserAccount u = base(UserType.STAFF, passwordHash, now);
        u.username = username;
        u.status = UserStatus.ACTIVE;
        u.mustChangePassword = true;
        u.roles.addAll(roles);
        return u;
    }

    /** Bước 1 của đăng ký: giữ chỗ SĐT, chưa đăng nhập được cho tới khi có hồ sơ khách hàng. */
    public static UserAccount newPendingCustomer(String phone, String passwordHash, Instant now) {
        UserAccount u = base(UserType.CUSTOMER, passwordHash, now);
        u.phone = phone;
        u.status = UserStatus.PENDING;
        return u;
    }

    private static UserAccount base(UserType type, String passwordHash, Instant now) {
        UserAccount u = new UserAccount();
        u.publicId = UUID.randomUUID();
        u.userType = type;
        u.passwordHash = passwordHash;
        u.passwordChangedAt = now;
        return u;
    }

    /** Bước 3 của đăng ký: đã có hồ sơ bên customer-service. */
    public void activateCustomer(long customerId, Role customerRole) {
        if (userType != UserType.CUSTOMER || status != UserStatus.PENDING) {
            throw new IllegalStateException("Chỉ kích hoạt được tài khoản khách đang PENDING");
        }
        this.customerId = customerId;
        this.status = UserStatus.ACTIVE;
        this.roles.add(customerRole);
    }

    /** Tên dùng để đăng nhập: username (nhân viên) hoặc SĐT (khách). */
    public String loginId() {
        return userType == UserType.STAFF ? username : phone;
    }

    public boolean isActive() {
        return status == UserStatus.ACTIVE;
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    public boolean hasRole(String roleCode) {
        return roles.stream().anyMatch(r -> r.getCode().equals(roleCode));
    }

    /**
     * Ghi nhận một lần sai mật khẩu.
     *
     * @return true nếu lần sai này làm tài khoản bị khóa tạm
     */
    public boolean recordFailedLogin(int maxAttempts, Duration lockDuration, Instant now) {
        failedLoginCount++;
        if (failedLoginCount >= maxAttempts) {
            lockedUntil = now.plus(lockDuration);
            failedLoginCount = 0;   // hết khóa thì được thử lại đủ maxAttempts lần
            return true;
        }
        return false;
    }

    public void recordSuccessfulLogin(Instant now) {
        failedLoginCount = 0;
        lockedUntil = null;
        lastLoginAt = now;
    }

    /** Tự đổi mật khẩu. */
    public void changePassword(String newHash, Instant now) {
        this.passwordHash = newHash;
        this.passwordChangedAt = now;
        this.mustChangePassword = false;
    }

    /** Thuật toán băm được nâng cấp (vd tăng cost bcrypt): băm lại ngay lúc user đăng nhập đúng. */
    public void upgradePasswordHash(String newHash) {
        this.passwordHash = newHash;
    }

    /** Quản trị viên đặt mật khẩu tạm: user phải đổi lại ở lần đăng nhập tới. */
    public void resetPassword(String temporaryHash, Instant now) {
        this.passwordHash = temporaryHash;
        this.passwordChangedAt = now;
        this.mustChangePassword = true;
        unlock();
    }

    public void disable() {
        this.status = UserStatus.DISABLED;
    }

    public void enable() {
        if (status == UserStatus.DISABLED) {
            this.status = UserStatus.ACTIVE;
        }
    }

    public void unlock() {
        this.failedLoginCount = 0;
        this.lockedUntil = null;
    }

    public void replaceRoles(Set<Role> newRoles) {
        roles.clear();
        roles.addAll(newRoles);
    }

    public List<String> roleCodes() {
        return roles.stream().map(Role::getCode).sorted().toList();
    }

    public List<String> permissionCodes() {
        TreeSet<String> perms = new TreeSet<>();
        for (Role role : roles) {
            role.getPermissions().forEach(p -> perms.add(p.getCode()));
        }
        return List.copyOf(perms);
    }
}
