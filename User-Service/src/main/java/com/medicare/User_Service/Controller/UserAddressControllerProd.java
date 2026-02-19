package com.medicare.User_Service.Controller;


import com.medicare.User_Service.Models.Address;
import com.medicare.User_Service.Payload.Request.AddressRequest;
import com.medicare.User_Service.Payload.Response.MessageResponse;
import com.medicare.User_Service.Service.UserAddressService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Profile("prod")
@RequiredArgsConstructor
@RestController
@RequestMapping("/user/address")
public class UserAddressControllerProd {

    private final UserAddressService userService;

    /**
     * Add a new address for the authenticated user
     */
    @PostMapping("/addAddress")
    public ResponseEntity<MessageResponse> addAddress(
            HttpServletRequest request,
            @Valid @RequestBody AddressRequest addressRequest) {

        String userId = request.getHeader("X-User-Id");
        MessageResponse messageResponse = userService.addAddresses(userId, addressRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(messageResponse);
    }

    /**
     * Update an existing address for the authenticated user
     */
    @PutMapping("/{addressId}")
    public ResponseEntity<MessageResponse> updateAddress(
            HttpServletRequest request,
            @PathVariable String addressId,
            @Valid @RequestBody AddressRequest addressRequest) {

        String userId = request.getHeader("X-User-Id");
        MessageResponse messageResponse = userService.updateAddress(userId, addressId, addressRequest);
        return ResponseEntity.ok(messageResponse);
    }

    /**
     * Get all addresses for the authenticated user
     */
    @GetMapping
    public ResponseEntity<List<Address>> getAddresses(HttpServletRequest request) {
        String userId = request.getHeader("X-User-Id");
        List<Address> addresses = userService.getAddress(userId);
        return ResponseEntity.ok(addresses);
    }

    /**
     * Get a specific address by ID for the authenticated user
     */
    @GetMapping("/{addressId}")
    public ResponseEntity<Address> getAddressById(
            HttpServletRequest request,
            @PathVariable String addressId) {

        String userId = request.getHeader("X-User-Id");
        Address address = userService.getAddressById(userId, addressId);
        return ResponseEntity.ok(address);
    }

    /**
     * Delete an address for the authenticated user
     */
    @DeleteMapping("/{addressId}")
    public ResponseEntity<MessageResponse> deleteAddress(
            HttpServletRequest request,
            @PathVariable String addressId) {

        String userId = request.getHeader("X-User-Id");
        MessageResponse messageResponse = userService.deleteAddress(userId, addressId);
        return ResponseEntity.ok(messageResponse);
    }
}
