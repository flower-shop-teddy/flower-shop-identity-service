package com.flowershop.identity.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** Quyền làm MỘT việc, đặt tên resource:action, ví dụ flower:write. Chỉ thêm qua migration. */
@Entity
@Table(name = "permission")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100, updatable = false)
    private String code;

    @Column(nullable = false)
    private String description;
}
