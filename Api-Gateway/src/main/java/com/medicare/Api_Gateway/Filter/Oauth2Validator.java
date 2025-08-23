package com.medicare.Api_Gateway.Filter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

@Component
public class Oauth2Validator {
    private static final String GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";

    public static boolean validateGoogleToken(String token) {
        try {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL(GOOGLE_JWKS_URL));

            jwtProcessor.setJWSKeySelector(new JWSAlgorithmFamilyJWSKeySelector<>(null, keySource));

            // Parse and validate
            SignedJWT signedJWT = SignedJWT.parse(token);
            jwtProcessor.process(signedJWT, null);

            return true;
        } catch (ParseException | MalformedURLException | JOSEException e) {
            e.printStackTrace();
            return false;
        } catch (Exception e) {
            return false;
        }
    }

}
