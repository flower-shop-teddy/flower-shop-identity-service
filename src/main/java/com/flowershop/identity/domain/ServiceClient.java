package com.flowershop.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Tài khoản của một service, dùng để xin service token (client_credentials). */
@Entity
@Table(name = "service_client")
@EntityListeners(AuditingEntityListener.class)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ServiceClient {

    public enum Status { ACTIVE, DISABLED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false, unique = true, length = 50, updatable = false)
    private String clientId;

    @Column(name = "secret_hash", nullable = false)
    private String secretHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Status status;

    @ManyToMany
    @JoinTable(name = "service_client_permission",
            joinColumns = @JoinColumn(name = "service_client_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    private Set<Permission> permissions = new HashSet<>();

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

    public static ServiceClient create(String clientId, String secretHash, Collection<Permission> permissions) {
        ServiceClient c = new ServiceClient();
        c.clientId = clientId;
        c.secretHash = secretHash;
        c.status = Status.ACTIVE;
        c.permissions.addAll(permissions);
        return c;
    }

    public boolean isActive() {
        return status == Status.ACTIVE;
    }

    public void disable() {
        status = Status.DISABLED;
    }

    /** Sắp xếp để token ổn định, dễ đọc khi debug. */
    public List<String> permissionCodes() {
        return permissions.stream().map(Permission::getCode).sorted().toList();
    }
}
