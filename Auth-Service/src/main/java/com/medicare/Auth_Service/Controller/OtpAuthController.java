package com.medicare.Auth_Service.Controller;

import com.medicare.Auth_Service.DTO.Request.OtpVerifyRequest;
import com.medicare.Auth_Service.Services.OtpService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
public class OtpAuthController {
    private final OtpService otpService;

    @PostMapping("/send-otp")
    ResponseEntity<String> send_Otp(@RequestParam String phoneNumber)
    {
        String res=otpService.requestOtp(phoneNumber);
        return ResponseEntity.ok(res);
    }
//    @PostMapping("/verify-otp")
//    ResponseEntity<String> verify_Otp(@RequestBody OtpVerifyRequest otpVerifyRequest)
//    {
//        Boolean res=otpService.verify(otpVerifyRequest);
//        return ResponseEntity.ok(res?"Wrong Verification Code":"Successfully Verified");
//    }

}
