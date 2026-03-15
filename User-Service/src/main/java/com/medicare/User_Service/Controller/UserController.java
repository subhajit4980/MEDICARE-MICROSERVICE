package com.medicare.User_Service.Controller;

import com.medicare.User_Service.DTO.Request.ProfileRequest;
import com.medicare.User_Service.DTO.Response.UserProfileResponse;
import com.medicare.User_Service.DTO.Response.UserSummaryResponse;
import com.medicare.User_Service.Service.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/user/")
public class UserController {
    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    private final UserProfileService userProfileService;

    @PostMapping("/updateProfile")
    public ResponseEntity<UserProfileResponse> updateUserProfile(@Valid @RequestBody ProfileRequest profileRequest,
                                                                 HttpServletRequest request) {
        String userId = request.getHeader("X-User-Id");
        log.info("Received profile update request for userId={}", userId);
        UserProfileResponse userProfileResponse = userProfileService.updateUserProfile(profileRequest, userId);
        return ResponseEntity.ok(userProfileResponse);
    }

    @GetMapping("")
    public ResponseEntity<UserProfileResponse> getUser(HttpServletRequest request) {
        String userId = request.getHeader("X-User-Id");
        log.debug("Received get user profile request for userId={}", userId);
        return ResponseEntity.ok(userProfileService.getUserProfile(userId));
    }

    // Internal endpoint for other services
    @GetMapping("/internal/{userId}")
    public ResponseEntity<UserSummaryResponse> getUserSummary(@PathVariable String userId) {
        log.debug("Received internal user summary request for userId={}", userId);
        return ResponseEntity.ok(userProfileService.getUserSummary(userId));
    }
}