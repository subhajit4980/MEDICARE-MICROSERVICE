package com.medicare.User_Service.Controller;


import com.medicare.User_Service.Model.Address;
import com.medicare.User_Service.DTO.Request.AddressRequest;
import com.medicare.User_Service.DTO.Response.MessageResponse;
import com.medicare.User_Service.Service.UserAddressService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Profile("prod")
@RequiredArgsConstructor
@RestController
@RequestMapping("/user/address")
public class UserAddressController {

    private static final Logger log = LoggerFactory.getLogger(UserAddressController.class);

    private final UserAddressService userService;

    /**
     * Add a new address for the authenticated user
     */
    @PostMapping("/addAddress")
    public ResponseEntity<MessageResponse> addAddress(
            HttpServletRequest request,
            @Valid @RequestBody AddressRequest addressRequest) {

        String userId = request.getHeader("X-User-Id");
        log.info("HTTP POST /user/address/addAddress by userId={}", userId);
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
        log.info("HTTP PUT /user/address/{} by userId={}", addressId, userId);
        MessageResponse messageResponse = userService.updateAddress(userId, addressId, addressRequest);
        return ResponseEntity.ok(messageResponse);
    }

    /**
     * Get all addresses for the authenticated user
     */
    @GetMapping
    public ResponseEntity<List<Address>> getAddresses(HttpServletRequest request) {
        String userId = request.getHeader("X-User-Id");
        log.debug("HTTP GET /user/address by userId={}", userId);
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
        log.debug("HTTP GET /user/address/{} by userId={}", addressId, userId);
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
        log.info("HTTP DELETE /user/address/{} by userId={}", addressId, userId);
        MessageResponse messageResponse = userService.deleteAddress(userId, addressId);
        return ResponseEntity.ok(messageResponse);
    }

    /**
     * Mark an address as the default for the authenticated user
     */
    @PutMapping("/{addressId}/make-default")
    public ResponseEntity<MessageResponse> makeDefaultAddress(
            HttpServletRequest request,
            @PathVariable String addressId
    ) {
        String userId = request.getHeader("X-User-Id");
        log.info("HTTP PUT /user/address/{}/make-default by userId={}", addressId, userId);
        MessageResponse messageResponse = userService.makeDefaultAddress(userId, addressId);
        return ResponseEntity.ok(messageResponse);
    }
}
