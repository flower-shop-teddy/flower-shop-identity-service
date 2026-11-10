package com.flowershop.identity.repository;

import com.flowershop.identity.domain.ServiceClient;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ServiceClientRepository extends JpaRepository<ServiceClient, Long> {

    /** Lấy luôn permission: cấp token cần danh sách quyền, tránh truy vấn thêm (N+1). */
    @EntityGraph(attributePaths = "permissions")
    Optional<ServiceClient> findByClientId(String clientId);

    boolean existsByClientId(String clientId);
}
