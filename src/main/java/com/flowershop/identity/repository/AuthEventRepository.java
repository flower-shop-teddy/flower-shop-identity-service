package com.flowershop.identity.repository;

import com.flowershop.identity.domain.AuthEvent;
import com.flowershop.identity.domain.AuthEventType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuthEventRepository extends JpaRepository<AuthEvent, Long> {

    List<AuthEvent> findByUserIdAndEventTypeOrderByIdDesc(Long userId, AuthEventType eventType);
}
