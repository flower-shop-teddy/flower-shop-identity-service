package com.flowershop.identity.repository;

import com.flowershop.common.security.UserType;
import com.flowershop.identity.domain.UserAccount;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface UserAccountRepository extends JpaRepository<UserAccount, Long> {

    /**
     * SELECT ... FOR UPDATE: hai request đăng nhập sai cùng lúc phải xếp hàng,
     * nếu không cả hai cùng đọc failed_login_count = 4 rồi cùng ghi 5 -> mất một lần đếm.
     * Không JOIN FETCH roles ở đây: Postgres không cho FOR UPDATE trên phía nullable của outer join.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from UserAccount u where u.username = :username")
    Optional<UserAccount> findByUsernameForUpdate(@Param("username") String username);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from UserAccount u where u.phone = :phone")
    Optional<UserAccount> findByPhoneForUpdate(@Param("phone") String phone);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from UserAccount u where u.id = :id")
    Optional<UserAccount> findByIdForUpdate(@Param("id") Long id);

    Optional<UserAccount> findByPublicId(UUID publicId);

    boolean existsByUsername(String username);

    boolean existsByPhone(String phone);

    boolean existsByRoles_Code(String roleCode);

    Page<UserAccount> findByUserType(UserType userType, Pageable pageable);
}
