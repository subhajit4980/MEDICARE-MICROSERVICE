package com.medicare.Auth_Service.Services;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Optional;

@Component
public class JwtUtils {
    @Value("${Medicare.app.jwtSecret}")
    private String jwtSecret;
    @Value("${Medicare.app.jwtExpirationMs}")
    public Long jwtExpirationMs;
    @Value("${Medicare.app.refresh-token-expiration}")
    public Long refresh_token_expiration;
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    private String userId;
    public  String generateRefreshToken(CustomUserDetails userDetails ,String userId) {
        this.userId=userId;
        return  token(userDetails,refresh_token_expiration);
    }
    public String generateToken(CustomUserDetails userDetails) {
        return token(userDetails, jwtExpirationMs);
    }

    public String token(CustomUserDetails userDetails, Long expiration ) {
        return Jwts.builder()
                .setSubject((userDetails.getUsername()))
                .claim("password", userDetails.getPassword())
                .claim("userId",userId)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date((new Date()).getTime() + expiration))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String getEmailFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(getSignKey()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    public String getUserIdFromJwtToken(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(getSignKey()).build()
                .parseClaimsJws(token).getBody();
        return String.valueOf(claims.get("userId"));
    }

    public boolean isTokenExpired(String token) {
        try {
            return claims(token).getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true; // Definitely expired
        } catch (MalformedJwtException | SignatureException | UnsupportedJwtException | IllegalArgumentException e) {
            System.err.println("⚠️ Invalid token: " + e.getMessage());
            return true;
        }
    }

    private Claims claims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = getEmailFromJwtToken(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(getSignKey()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
