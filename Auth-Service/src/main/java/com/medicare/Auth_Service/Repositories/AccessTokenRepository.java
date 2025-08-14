package com.medicare.Auth_Service.Repositories;


import com.medicare.Auth_Service.Model.AccessToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;
import java.util.Optional;

public interface AccessTokenRepository extends MongoRepository<AccessToken, String> {

    // Custom query to get all valid (non-revoked and non-expired) tokens of a user
    @Query("{'user.userId': ?0, 'revoked': false, 'expired': false}")
    List<AccessToken> findTokensByUserId(String userId);

    // Find a token by its value (either for access or refresh token)
    Optional<AccessToken> findByToken(String token);
}
