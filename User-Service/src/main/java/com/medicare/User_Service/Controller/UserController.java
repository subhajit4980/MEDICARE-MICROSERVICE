package com.medicare.User_Service.Controller;

import com.medicare.User_Service.Models.UserProfile;
import com.medicare.User_Service.Payload.Response.MessageResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/user/")
public class UserController {

    @PostMapping("")
//    public ResponseEntity<UserProfile> setUserProfile()

    @GetMapping("")
    public ResponseEntity<MessageResponse> getUser(HttpServletRequest request) {
        String userId = request.getHeader("X-User-Id");

        return null;
    }

}
