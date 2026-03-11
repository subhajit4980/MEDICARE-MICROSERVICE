package com.medicare.User_Service.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medicare.User_Service.DTO.Request.ProfileRequest;
import com.medicare.User_Service.DTO.Response.MessageResponse;
import com.medicare.User_Service.DTO.Response.UserProfileResponse;
import com.medicare.User_Service.Exception.UserException;
import com.medicare.User_Service.Model.UserProfile;
import com.medicare.User_Service.Repository.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class UserProfileServiceImpl implements UserProfileService {
    private final UserProfileRepository userProfileRepository;
    ModelMapper modelMapper = new ModelMapper();

    @Override
    public UserProfileResponse updateUserProfile(ProfileRequest profileRequest,String userId) {
        UserProfile userProfile=userProfileRepository.findByUserId(userId).orElseThrow(()-> new UserException(HttpStatus.NOT_FOUND,"User not found"));
        userProfile.setProfileImageUrl(profileRequest.getProfileImageUrl());
        userProfile.setUpdatedAt(LocalDateTime.now());
        userProfile.setDateOfBirth(profileRequest.getDateOfBirth());
        userProfileRepository.save(userProfile);
        return modelMapper.map(userProfile,UserProfileResponse.class);
    }

    @Override
    public UserProfileResponse getUserProfile(String userId) {
        UserProfile userProfile=userProfileRepository.findByUserId(userId).orElseThrow(()->new UserException(HttpStatus.NOT_FOUND,"User not found"));
        return modelMapper.map(userProfile,UserProfileResponse.class);
    }
}
