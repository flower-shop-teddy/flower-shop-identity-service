package com.flowershop.identity.repository;

import com.flowershop.identity.domain.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

public interface PermissionRepository extends JpaRepository<Permission, Long> {

    List<Permission> findByCodeIn(Collection<String> codes);
}
