package com.flowershop.identity.service;

import com.flowershop.common.api.PageResponse;
import com.flowershop.common.error.BusinessException;
import com.flowershop.common.security.AuthenticatedUser;
import com.flowershop.common.security.CurrentUser;
import com.flowershop.common.security.UserType;
import com.flowershop.identity.domain.AuthEventType;
import com.flowershop.identity.domain.RefreshToken;
import com.flowershop.identity.domain.Role;
import com.flowershop.identity.domain.UserAccount;
import com.flowershop.identity.dto.CreateStaffRequest;
import com.flowershop.identity.dto.TemporaryPasswordResponse;
import com.flowershop.identity.dto.UserResponse;
import com.flowershop.identity.error.IdentityErrorCode;
import com.flowershop.identity.repository.RoleRepository;
import com.flowershop.identity.repository.UserAccountRepository;
import com.flowershop.identity.security.ClientInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Quản trị tài khoản. Ngoài permission ở controller (@PreAuthorize), còn các luật mà permission không diễn tả được:
 * <ul>
 *   <li>Không tự thao tác trên chính mình (tự nâng quyền, tự mở khóa...).</li>
 *   <li>Chỉ ADMIN mới đụng tới tài khoản ADMIN hoặc gán/bỏ role ADMIN (chống leo thang đặc quyền).</li>
 *   <li>Role CUSTOMER chỉ có qua luồng đăng ký, không gán tay cho nhân viên.</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserAdminService {

    private static final int MAX_PAGE_SIZE = 100;

    private final UserAccountRepository users;
    private final RoleRepository roles;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final RefreshTokenService refreshTokens;
    private final AuthEventRecorder events;
    private final Clock clock;

    @Transactional(readOnly = true)
    public PageResponse<UserResponse> list(UserType type, int page, int size) {
        PageRequest pageable = PageRequest.of(Math.max(page, 0), Math.clamp(size, 1, MAX_PAGE_SIZE),
                Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<UserAccount> result = type == null ? users.findAll(pageable) : users.findByUserType(type, pageable);
        return new PageResponse<>(result.getContent().stream().map(u -> UserMapper.toResponse(u, clock.instant())).toList(),
                result.getNumber(), result.getSize(), result.getTotalElements(), result.getTotalPages());
    }

    @Transactional(readOnly = true)
    public UserResponse get(UUID publicId) {
        return UserMapper.toResponse(find(publicId), clock.instant());
    }

    @Transactional
    public TemporaryPasswordResponse createStaff(CreateStaffRequest req, ClientInfo client) {
        String username = LoginIds.normalizeUsername(req.username());
        Set<Role> newRoles = resolveStaffRoles(req.roles());
        if (users.existsByUsername(username)) {
            throw new BusinessException(IdentityErrorCode.USERNAME_ALREADY_EXISTS);
        }
        String temporary = passwordPolicy.generateTemporary();
        UserAccount staff;
        try {
            staff = users.saveAndFlush(UserAccount.newStaff(username, passwordEncoder.encode(temporary),
                    newRoles, clock.instant()));
        } catch (DataIntegrityViolationException e) {
            throw new BusinessException(IdentityErrorCode.USERNAME_ALREADY_EXISTS);
        }
        events.record(AuthEventType.USER_CREATED, staff, client, "roles=" + staff.roleCodes());
        log.info("Staff created: user={} roles={}", staff.getPublicId(), staff.roleCodes());
        return new TemporaryPasswordResponse(UserMapper.toResponse(staff, clock.instant()), temporary);
    }

    @Transactional
    public UserResponse assignRoles(UUID publicId, Set<String> roleCodes, ClientInfo client) {
        UserAccount target = findForManage(publicId);
        if (target.getUserType() != UserType.STAFF) {
            throw new BusinessException(IdentityErrorCode.NOT_A_STAFF_ACCOUNT);
        }
        Set<Role> newRoles = resolveStaffRoles(roleCodes);
        List<String> before = target.roleCodes();
        target.replaceRoles(newRoles);
        // Quyền mới chỉ có hiệu lực từ token sau; thu hồi refresh token để buộc lấy token mới sớm nhất có thể
        refreshTokens.revokeAllOfUser(target.getId(), RefreshToken.RevokeReason.ADMIN_ACTION);
        events.record(AuthEventType.ROLE_CHANGED, target, client, before + " -> " + target.roleCodes());
        log.info("Roles changed: user={} {} -> {}", target.getPublicId(), before, target.roleCodes());
        return UserMapper.toResponse(users.saveAndFlush(target), clock.instant());
    }

    @Transactional
    public UserResponse disable(UUID publicId, ClientInfo client) {
        UserAccount target = findForManage(publicId);
        target.disable();
        refreshTokens.revokeAllOfUser(target.getId(), RefreshToken.RevokeReason.ADMIN_ACTION);
        events.record(AuthEventType.USER_DISABLED, target, client, null);
        return UserMapper.toResponse(users.saveAndFlush(target), clock.instant());
    }

    @Transactional
    public UserResponse enable(UUID publicId, ClientInfo client) {
        UserAccount target = findForManage(publicId);
        target.enable();
        events.record(AuthEventType.USER_ENABLED, target, client, null);
        return UserMapper.toResponse(users.saveAndFlush(target), clock.instant());
    }

    @Transactional
    public UserResponse unlock(UUID publicId, ClientInfo client) {
        UserAccount target = findForManage(publicId);
        target.unlock();
        events.record(AuthEventType.USER_UNLOCKED, target, client, null);
        return UserMapper.toResponse(users.saveAndFlush(target), clock.instant());
    }

    @Transactional
    public TemporaryPasswordResponse resetPassword(UUID publicId, ClientInfo client) {
        UserAccount target = findForManage(publicId);
        String temporary = passwordPolicy.generateTemporary();
        target.resetPassword(passwordEncoder.encode(temporary), clock.instant());
        refreshTokens.revokeAllOfUser(target.getId(), RefreshToken.RevokeReason.ADMIN_ACTION);
        events.record(AuthEventType.PASSWORD_RESET, target, client, null);
        return new TemporaryPasswordResponse(UserMapper.toResponse(users.saveAndFlush(target), clock.instant()),
                temporary);
    }

    private UserAccount find(UUID publicId) {
        return users.findByPublicId(publicId)
                .orElseThrow(() -> new BusinessException(IdentityErrorCode.USER_NOT_FOUND));
    }

    /** Lấy tài khoản + khóa dòng, rồi kiểm tra người đang thao tác có được đụng vào tài khoản này không. */
    private UserAccount findForManage(UUID publicId) {
        UserAccount target = users.findByIdForUpdate(find(publicId).getId()).orElseThrow();
        AuthenticatedUser actor = CurrentUser.require();
        if (target.getPublicId().toString().equals(actor.subject())) {
            throw new BusinessException(IdentityErrorCode.CANNOT_MODIFY_SELF);
        }
        if (target.hasRole(Role.ADMIN) && !isAdmin(actor)) {
            throw new BusinessException(IdentityErrorCode.ADMIN_REQUIRED);
        }
        return target;
    }

    private Set<Role> resolveStaffRoles(Set<String> codes) {
        Set<String> wanted = new HashSet<>();
        codes.forEach(c -> wanted.add(c.strip().toUpperCase(Locale.ROOT)));
        if (wanted.contains(Role.CUSTOMER)) {
            throw new BusinessException(IdentityErrorCode.INVALID_ROLE, "Không gán role CUSTOMER cho nhân viên");
        }
        if (wanted.contains(Role.ADMIN) && !isAdmin(CurrentUser.require())) {
            throw new BusinessException(IdentityErrorCode.ADMIN_REQUIRED);
        }
        List<Role> found = roles.findByCodeIn(wanted);
        if (found.size() != wanted.size()) {
            throw new BusinessException(IdentityErrorCode.INVALID_ROLE, "Có role không tồn tại: " + wanted);
        }
        return new HashSet<>(found);
    }

    private static boolean isAdmin(AuthenticatedUser actor) {
        return actor.roles().contains(Role.ADMIN);
    }
}
