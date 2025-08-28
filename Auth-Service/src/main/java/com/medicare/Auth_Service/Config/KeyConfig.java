package com.medicare.Auth_Service.Config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.KeyUse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;

@Configuration
public class KeyConfig {

    @Value("${app.jwks.key-id}")
    private String keyId;

    // ❗ In production: load from Vault/Keystore/PEM — do NOT generate at runtime.
    @Bean
    public RSAKey rsaJwk() throws Exception {
        return new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(keyId)
                .generate();
    }

    @Bean
    public JWKSet jwkSet(RSAKey rsaJwk) {
        return new JWKSet(rsaJwk.toPublicJWK());
    }
}
