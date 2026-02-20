package com.medicare.User_Service.Service;

import com.medicare.User_Service.Exception.UserException;
import com.medicare.User_Service.Model.Address;
import com.medicare.User_Service.DTO.Request.AddressRequest;
import com.medicare.User_Service.DTO.Response.MessageResponse;
import com.medicare.User_Service.Repository.AddressRepository;
import jakarta.validation.Valid;
import org.apache.commons.text.StringEscapeUtils;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserAddressServiceImpl implements UserAddressService {
    private static final Logger log = LoggerFactory.getLogger(UserAddressServiceImpl.class);
    ModelMapper modelMapper = new ModelMapper();
    private final AddressRepository addressRepository;

    @Transactional
    @Override
    public MessageResponse addAddresses(String userId, AddressRequest addressRequest) {
        try {
            // 1. Validate input
            if (addressRequest == null || userId == null) {
                throw new UserException(HttpStatus.BAD_REQUEST, "Invalid address request");
            }
            // 2. Sanitize input (prevent injection or unwanted data)
            sanitizeAddressRequest(addressRequest);
            // 3. Map DTO → Entity
            Address newAddress = modelMapper.map(addressRequest, Address.class);
            newAddress.setDefault(false);
            newAddress.setUserId(userId);
            // 4. Save securely
            addressRepository.save(newAddress);
            // 5. Return success message
            return new MessageResponse("Address added successfully",newAddress);

        } catch (UserException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error adding address for user: {}", e.getMessage(), e);
            throw new UserException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to add address");
        }
    }

    @Override
    @Transactional
    public MessageResponse updateAddress(@Valid String userId, String addressId, AddressRequest addressRequest) {
        try {
            Address userAddress = addressRepository.findById(addressId)
                    .orElseThrow(() -> new UserException(HttpStatus.NOT_FOUND, "Address not found"));
            if (userAddress.getUserId() == null || !userAddress.getUserId().equals(userId)) {
                throw new UserException(HttpStatus.FORBIDDEN, "You are not authorized to modify this address");
            }
            sanitizeAddressRequest(addressRequest);
            modelMapper.map(addressRequest, userAddress);
            addressRepository.save(userAddress);
            return new MessageResponse("Address updated successfully",userAddress);
        } catch (Exception e) {
            log.error("Error adding address for user: {}", e.getMessage(), e);
            throw new UserException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to update address");
        }
    }

    @Override
    public List<Address> getAddress(String userId) {
        return (addressRepository.findByUserId(userId).orElseThrow(() -> new UserException(HttpStatus.BAD_REQUEST, "Address not found")));
    }

    @Override
    public Address getAddressById(String userId, String addressId) {
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new UserException(HttpStatus.NOT_FOUND, "Address not found"));

        if (!address.getUserId().equals(userId)) {
            throw new UserException(HttpStatus.FORBIDDEN, "You are not authorized to view this address");
        }

        return address;
    }

    @Override
    @Transactional
    public MessageResponse deleteAddress(String userId, String addressId) {
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new UserException(HttpStatus.NOT_FOUND, "Address not found"));

        if (!address.getUserId().equals(userId)) {
            throw new UserException(HttpStatus.FORBIDDEN, "You are not authorized to delete this address");
        }

        addressRepository.delete(address);
        return new MessageResponse("Address deleted successfully",address);
    }

    private void sanitizeAddressRequest(AddressRequest request) {
        request.setCity(StringEscapeUtils.escapeHtml4(request.getCity()));
        request.setStreet(StringEscapeUtils.escapeHtml4(request.getStreet()));
        request.setState(StringEscapeUtils.escapeHtml4(request.getState()));
        request.setCountry(StringEscapeUtils.escapeHtml4(request.getCountry()));
    }

}
