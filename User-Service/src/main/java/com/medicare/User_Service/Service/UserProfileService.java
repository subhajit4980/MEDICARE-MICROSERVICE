package com.medicare.User_Service.Service;

import com.medicare.User_Service.DTO.Request.ProfileRequest;
import com.medicare.User_Service.DTO.Response.UserProfileResponse;
import com.medicare.User_Service.DTO.Response.UserSummaryResponse;

public interface UserProfileService {
    UserProfileResponse updateUserProfile(ProfileRequest profileRequest,String userId);
    UserProfileResponse getUserProfile(String userId);
    UserSummaryResponse getUserSummary(String userId);
}
