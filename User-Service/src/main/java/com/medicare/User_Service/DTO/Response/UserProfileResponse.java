package com.medicare.User_Service.DTO.Response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Date;
@Data
@Builder
public class UserProfileResponse {
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

    // Derived
    private Double profileCompleteness; // 0.0 - 1.0

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
