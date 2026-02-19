package com.medicare.User_Service.Service;

import com.medicare.User_Service.Models.UserProfile;
import com.medicare.User_Service.Payload.Response.MessageResponse;

public interface UserProfileService {
    void addUserProfile( String payload, String key);

}
