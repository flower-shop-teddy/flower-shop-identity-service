package com.flowershop.identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

// Quét thêm package common để nhận GlobalExceptionHandler, CorrelationIdFilter, SecurityExceptionHandler từ common-lib
@SpringBootApplication(scanBasePackages = {"com.flowershop.identity", "com.flowershop.common"})
@ConfigurationPropertiesScan
public class IdentityServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(IdentityServiceApplication.class, args);
    }
}
