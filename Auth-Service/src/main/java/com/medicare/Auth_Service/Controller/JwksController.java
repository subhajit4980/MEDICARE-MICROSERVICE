package com.medicare.Auth_Service.Controller;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class JwksController {
    private final JWKSet jwkSet;
    @Value("${app.issuer}") private String issuer;

    public JwksController(JWKSet jwkSet) { this.jwkSet = jwkSet; }

    @GetMapping(value="/.well-known/jwks.json" ,produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> jwks() {
        return jwkSet.toPublicJWKSet().toJSONObject();
    }

    @GetMapping("/.well-known/openid-configuration")
    public Map<String, Object> discovery() {
        return Map.of(
                "issuer", issuer,
                "jwks_uri", issuer + "/.well-known/jwks.json"
        );
    }
}
