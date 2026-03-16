package com.medicare.User_Service.Service;

import com.medicare.User_Service.DTO.Request.ProfileRequest;
import com.medicare.User_Service.DTO.Response.UserProfileResponse;
import com.medicare.User_Service.DTO.Response.UserSummaryResponse;
import com.medicare.User_Service.Exception.UserException;
import com.medicare.User_Service.Mapper.UserProfileMapper;
import com.medicare.User_Service.Model.Address;
import com.medicare.User_Service.Model.UserProfile;
import com.medicare.User_Service.Repository.AddressRepository;
import com.medicare.User_Service.Repository.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserProfileServiceImpl implements UserProfileService {
    private static final Logger log = LoggerFactory.getLogger(UserProfileServiceImpl.class);

    private final UserProfileRepository userProfileRepository;
    private final AddressRepository addressRepository;
    private final UserProfileMapper userProfileMapper;

    @Override
    public UserProfileResponse updateUserProfile(ProfileRequest profileRequest,String userId) {
        log.info("Updating user profile for userId={}", userId);
        UserProfile userProfile = userProfileRepository.findByUserId(userId)
                .orElseThrow(() -> new UserException(HttpStatus.NOT_FOUND,"User not found"));

        userProfileMapper.updateFromRequest(profileRequest, userProfile);
        userProfile.setUpdatedAt(LocalDateTime.now());

        UserProfile saved = userProfileRepository.save(userProfile);
        log.debug("User profile updated for userId={} at={}", userId, saved.getUpdatedAt());
        return mapWithCompleteness(saved);
    }

    @Override
    public UserProfileResponse getUserProfile(String userId) {
        log.debug("Fetching user profile for userId={}", userId);
        UserProfile userProfile = userProfileRepository.findByUserId(userId)
                .orElseThrow(() -> new UserException(HttpStatus.NOT_FOUND,"User not found"));
        return mapWithCompleteness(userProfile);
    }

    @Override
    public List<UserProfileResponse> getAllUserProfile() {
        List<UserProfileResponse> userProfileResponses=new ArrayList<>();
        List<UserProfile> allUserProfile=userProfileRepository.findAll();
        allUserProfile.forEach(user->{
            userProfileResponses.add(userProfileMapper.toResponse(user));
        });
        return userProfileResponses;
    }

    @Override
    public UserSummaryResponse getUserSummary(String userId) {
        log.debug("Fetching user summary for userId={}", userId);
        UserProfile profile = userProfileRepository.findByUserId(userId)
                .orElseThrow(() -> new UserException(HttpStatus.NOT_FOUND, "User not found"));

        List<Address> addresses = addressRepository.findByUserId(userId).orElse(List.of());
        Address defaultAddress = addresses.stream()
                .filter(Address::isDefaultAddress)
                .findFirst()
                .orElse(null);

        return UserSummaryResponse.builder()
                .userId(profile.getUserId())
                .firstName(profile.getFirstName())
                .lastName(profile.getLastName())
                .profileImageUrl(profile.getProfileImageUrl())
                .language(profile.getLanguage())
                .timeZone(profile.getTimeZone())
                .preferredCurrency(profile.getPreferredCurrency())
                .marketingOptIn(profile.getMarketingOptIn())
                .defaultAddress(defaultAddress)
                .build();
    }

    private UserProfileResponse mapWithCompleteness(UserProfile profile) {
        UserProfileResponse response = userProfileMapper.toResponse(profile);

        int totalFields = 7;
        int filled = 0;
        if (profile.getFirstName() != null && !profile.getFirstName().isBlank()) filled++;
        if (profile.getLastName() != null && !profile.getLastName().isBlank()) filled++;
        if (profile.getDateOfBirth() != null) filled++;
        if (profile.getProfileImageUrl() != null && !profile.getProfileImageUrl().isBlank()) filled++;
        if (profile.getLanguage() != null && !profile.getLanguage().isBlank()) filled++;
        if (profile.getTimeZone() != null && !profile.getTimeZone().isBlank()) filled++;
        if (profile.getPreferredCurrency() != null && !profile.getPreferredCurrency().isBlank()) filled++;

        response.setProfileCompleteness(totalFields == 0 ? 0.0 : (filled * 1.0) / totalFields);
        return response;
    }
}
