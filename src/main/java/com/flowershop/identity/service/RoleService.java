package com.flowershop.identity.service;

import com.flowershop.identity.dto.RoleResponse;
import com.flowershop.identity.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roles;

    @Transactional(readOnly = true)
    public List<RoleResponse> list() {
        return roles.findAllByOrderByIdAsc().stream().map(UserMapper::toResponse).toList();
    }
}
