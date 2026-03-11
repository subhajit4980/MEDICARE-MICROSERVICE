package com.medicare.User_Service.Controller;

import com.medicare.User_Service.DTO.Request.ProfileRequest;
import com.medicare.User_Service.DTO.Response.UserProfileResponse;
import com.medicare.User_Service.Service.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/user/")
public class UserController {
    private final UserProfileService userProfileService;

    @PostMapping("/updateProfile")
    public ResponseEntity<UserProfileResponse> updateUserProfile(@Valid @RequestBody ProfileRequest profileRequest,
                                                                 HttpServletRequest request) {
        String userId = request.getHeader("X-User-Id");
        UserProfileResponse userProfileResponse = userProfileService.updateUserProfile(profileRequest, userId);
        return ResponseEntity.ok(userProfileResponse);
    }

    @GetMapping("")
    public ResponseEntity<UserProfileResponse> getUser(HttpServletRequest request) {
        String userId = request.getHeader("X-User-Id");
        return ResponseEntity.ok(userProfileService.getUserProfile(userId));
    }

}