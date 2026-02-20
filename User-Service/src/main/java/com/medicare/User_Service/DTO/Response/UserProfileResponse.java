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
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
