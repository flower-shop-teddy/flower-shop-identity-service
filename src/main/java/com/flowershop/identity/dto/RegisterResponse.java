package com.flowershop.identity.dto;

import java.util.UUID;

public record RegisterResponse(UUID publicId, Long customerId, String customerCode) {
}
