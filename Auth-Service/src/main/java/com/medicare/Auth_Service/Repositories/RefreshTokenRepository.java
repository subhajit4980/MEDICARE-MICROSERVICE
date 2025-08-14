package com.medicare.Auth_Service.Repositories;


import com.medicare.Auth_Service.Model.AccessToken;
import com.medicare.Auth_Service.Model.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    // Custom query to get all valid (non-revoked and non-expired) tokens of a user
    @Query("{'user.userId': ?0, 'revoked': false, 'expired': false}")
    List<RefreshToken> findRefreshTokensByUserId(String userId);

    // Find a token by its value (either for access or refresh token)
    Optional<RefreshToken> findByRefreshToken(String token);
}
