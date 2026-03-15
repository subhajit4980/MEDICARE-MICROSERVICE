package com.medicare.User_Service.Model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;
import java.util.Date;
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Document(collection = "UserProfiles")
public class UserProfile {

    @Id
    private String userId;

    private String firstName;
    private String lastName;
    private Date dateOfBirth;
    private String profileImageUrl;

    // Preferences
    private String language;
    private String timeZone;
    private String preferredCurrency;
    private Boolean marketingOptIn;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
