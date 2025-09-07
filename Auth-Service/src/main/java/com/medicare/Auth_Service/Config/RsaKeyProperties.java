package com.medicare.Auth_Service.Config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.jwks.rsa")
public record RsaKeyProperties(
        String publicKeyB64,
        String privateKeyB64
) {}
