package com.medicare.User_Service.Mapper;

import com.medicare.User_Service.Config.MapStructConfig;
import com.medicare.User_Service.DTO.Request.ProfileRequest;
import com.medicare.User_Service.DTO.Response.UserProfileResponse;
import com.medicare.User_Service.Model.UserProfile;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

@Mapper(config = MapStructConfig.class)
public interface UserProfileMapper {

    UserProfileResponse toResponse(UserProfile source);
    @Mapping(target = "userId", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    void updateFromRequest(ProfileRequest request, @MappingTarget UserProfile profile);
}
