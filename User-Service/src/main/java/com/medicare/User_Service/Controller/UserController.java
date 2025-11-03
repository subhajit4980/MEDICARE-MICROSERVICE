package com.medicare.User_Service.Controller;

import com.medicare.User_Service.Models.Address;
import com.medicare.User_Service.Payload.Request.AddressRequest;
import com.medicare.User_Service.Payload.Response.MessageResponse;
import com.medicare.User_Service.Service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/user")
public class UserController {
    private final UserService userService;
    @PostMapping("/addAddress")
    public ResponseEntity<MessageResponse> addAddress(@Valid @RequestBody AddressRequest addressRequest){
        MessageResponse messageResponse=userService.addAddresses(addressRequest);
        return new ResponseEntity<>(messageResponse, HttpStatus.CREATED);
    }
    @PutMapping("/updateAddress")
    public ResponseEntity<MessageResponse> updateAddress(@Valid @RequestBody Address addressRequest){
        MessageResponse messageResponse=userService.updateAddress(addressRequest);
        return new ResponseEntity<>(messageResponse, HttpStatus.OK);
    }
    @GetMapping("/address/{userId}")
    public ResponseEntity<List<Address>> getAddress(@Valid String userId) {
        return new ResponseEntity<>(userService.getAddress(userId), HttpStatus.OK);
    }
}
