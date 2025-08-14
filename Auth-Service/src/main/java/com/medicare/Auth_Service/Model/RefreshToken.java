package com.medicare.Auth_Service.Model;
import com.medicare.Auth_Service.Model.Enum.TokenType;
import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "RefreshToken") // MongoDB document for tokens
public class RefreshToken {

    @Id
    public String id;

    @Column(unique = true) // Refresh token
    public String refreshToken;

    @Enumerated(EnumType.STRING) // Type of token (only BEARER supported now)
    public TokenType tokenType = TokenType.BEARER;

    public boolean revoked; // true if user manually logs out or session is invalidated

    public boolean expired; // true if token is expired (based on time or logic)

    @DBRef
    private User user; // The user to whom the token belongs (MongoDB reference)
    private Date createdAt;
    private Date expiresAt;

}
