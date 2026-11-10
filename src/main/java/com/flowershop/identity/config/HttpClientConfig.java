package com.flowershop.identity.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flowershop.common.client.ServiceClientFactory;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class HttpClientConfig {

    /** @LoadBalanced: URL dạng http://customer-service được tra trên Eureka rồi chia tải giữa các instance. */
    @Bean
    @LoadBalanced
    public RestClient.Builder loadBalancedRestClientBuilder() {
        return RestClient.builder();
    }

    @Bean
    public ServiceClientFactory serviceClientFactory(RestClient.Builder loadBalancedRestClientBuilder,
                                                     ObjectMapper objectMapper) {
        return new ServiceClientFactory(loadBalancedRestClientBuilder, objectMapper);
    }
}
