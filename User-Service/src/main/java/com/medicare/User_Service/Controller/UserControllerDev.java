package com.medicare.User_Service.Controller;

import com.medicare.User_Service.Models.Address;
import com.medicare.User_Service.Payload.Request.AddressRequest;
import com.medicare.User_Service.Payload.Response.MessageResponse;
import com.medicare.User_Service.Service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Profile("dev")
@RequiredArgsConstructor
@RestController
@RequestMapping("/users/{userId}")
public class UserControllerDev {

    private final UserService userService;

    /**
     * Add a new address for the user
     */
    @PostMapping("/addresses")
    public ResponseEntity<MessageResponse> addAddress(
            @PathVariable String userId,
            @Valid @RequestBody AddressRequest addressRequest) {

        MessageResponse messageResponse = userService.addAddresses(userId, addressRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(messageResponse);
    }

    /**
     * Update an existing address for the user
     */
    @PutMapping("/addresses/{addressId}")
    public ResponseEntity<MessageResponse> updateAddress(
            @PathVariable String userId,
            @PathVariable String addressId,
            @Valid @RequestBody AddressRequest addressRequest) {

        MessageResponse messageResponse = userService.updateAddress(userId, addressId, addressRequest);
        return ResponseEntity.ok(messageResponse);
    }

    /**
     * Get all addresses for a user
     */
    @GetMapping("/addresses")
    public ResponseEntity<List<Address>> getAddresses(@PathVariable String userId) {
        List<Address> addresses = userService.getAddress(userId);
        return ResponseEntity.ok(addresses);
    }

    /**
     * Get a specific address by ID for a user
     */
    @GetMapping("/addresses/{addressId}")
    public ResponseEntity<Address> getAddressById(
            @PathVariable String userId,
            @PathVariable String addressId) {

        Address address = userService.getAddressById(userId, addressId);
        return ResponseEntity.ok(address);
    }

    /**
     * Delete an address for a user
     */
    @DeleteMapping("/addresses/{addressId}")
    public ResponseEntity<MessageResponse> deleteAddress(
            @PathVariable String userId,
            @PathVariable String addressId) {

        MessageResponse messageResponse = userService.deleteAddress(userId, addressId);
        return ResponseEntity.ok(messageResponse);
    }
}
