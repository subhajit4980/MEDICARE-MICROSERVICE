package com.medicare.User_Service.Service;

import com.medicare.User_Service.Exception.UserException;
import com.medicare.User_Service.Mapper.AddressMapper;
import com.medicare.User_Service.Model.Address;
import com.medicare.User_Service.DTO.Request.AddressRequest;
import com.medicare.User_Service.DTO.Response.MessageResponse;
import com.medicare.User_Service.Repository.AddressRepository;
import jakarta.validation.Valid;
import org.apache.commons.text.StringEscapeUtils;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserAddressServiceImpl implements UserAddressService {
    private static final Logger log = LoggerFactory.getLogger(UserAddressServiceImpl.class);
    private static final int MAX_ADDRESSES_PER_USER = 10;
    private final AddressRepository addressRepository;
    private final AddressMapper addressMapper;

    @Transactional
    @Override
    public MessageResponse addAddresses(String userId, AddressRequest addressRequest) {
            log.info("Adding address for userId={}", userId);
            // 1. Validate input
            if (addressRequest == null || userId == null) {
                throw new UserException(HttpStatus.BAD_REQUEST, "Invalid address request");
            }
            long existingCount = addressRepository.countByUserId(userId);
            if (existingCount >= MAX_ADDRESSES_PER_USER) {
                throw new UserException(HttpStatus.BAD_REQUEST, "Maximum number of addresses reached");
            }
            // 2. Sanitize input (prevent injection or unwanted data)
            sanitizeAddressRequest(addressRequest);
            // 3. Map DTO → Entity
            Address newAddress = addressMapper.toEntity(addressRequest);
            newAddress.setDefaultAddress(existingCount == 0);
            newAddress.setCreatedAt(LocalDateTime.now());
            newAddress.setUpdatedAt(LocalDateTime.now());
            newAddress.setUserId(userId);
            // 4. Save securely
            addressRepository.save(newAddress);
            log.debug("Address added for userId={} addressId={}", userId, newAddress.getAddressId());
            // 5. Return success message
            return new MessageResponse("Address added successfully",newAddress);

    }


    @Override
    @Transactional
    public MessageResponse updateAddress(@Valid String userId, String addressId, AddressRequest addressRequest) {
            log.info("Updating address addressId={} for userId={}", addressId, userId);
            Address userAddress = addressRepository.findById(addressId)
                    .orElseThrow(() -> new UserException(HttpStatus.NOT_FOUND, "Address not found"));
            if (!userAddress.getUserId().equals(userId)) {
                throw new UserException(HttpStatus.FORBIDDEN, "You are not authorized to modify this address");
            }
            sanitizeAddressRequest(addressRequest);
            addressMapper.updateFromRequest(addressRequest, userAddress);
            userAddress.setUpdatedAt(LocalDateTime.now());
            addressRepository.save(userAddress);
            log.debug("Address updated addressId={} for userId={}", addressId, userId);
            return new MessageResponse("Address updated successfully",userAddress);

    }

    @Override
    public List<Address> getAddress(String userId) {
        log.debug("Fetching all addresses for userId={}", userId);
        return (addressRepository.findByUserId(userId).orElseThrow(() -> new UserException(HttpStatus.BAD_REQUEST, "Address not found")));
    }

    @Override
    public Address getAddressById(String userId, String addressId) {
        log.debug("Fetching addressId={} for userId={}", addressId, userId);
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
        log.info("Deleting addressId={} for userId={}", addressId, userId);
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new UserException(HttpStatus.NOT_FOUND, "Address not found"));

        if (!address.getUserId().equals(userId)) {
            throw new UserException(HttpStatus.FORBIDDEN, "You are not authorized to delete this address");
        }
        boolean wasDefault = address.isDefaultAddress();
        addressRepository.delete(address);
        if (wasDefault) {
            List<Address> remaining = addressRepository.findByUserId(userId).orElse(List.of());
            if (!remaining.isEmpty()) {
                Address newDefault = remaining.get(0);
                newDefault.setDefaultAddress(true);
                addressRepository.save(newDefault);
                log.debug("Reassigned default address to addressId={} for userId={}", newDefault.getAddressId(), userId);
            }
        }
        return new MessageResponse("Address deleted successfully",address);
    }

    @Override
    @Transactional
    public MessageResponse makeDefaultAddress(String userId, String addressId) {
        log.info("Marking addressId={} as default for userId={}", addressId, userId);
        Address targetAddress = addressRepository.findById(addressId)
                .orElseThrow(() -> new UserException(HttpStatus.NOT_FOUND, "Address not found"));

        if (!userId.equals(targetAddress.getUserId())) {
            throw new UserException(HttpStatus.FORBIDDEN, "You are not authorized to modify this address");
        }

        List<Address> userAddresses = addressRepository.findByUserId(userId)
                .orElseThrow(() -> new UserException(HttpStatus.BAD_REQUEST, "No addresses found for user"));

        for (Address addr : userAddresses) {
            addr.setDefaultAddress(addr.getAddressId().equals(addressId));
        }

        addressRepository.saveAll(userAddresses);
        return new MessageResponse("Default address updated successfully", targetAddress);
    }

    private void sanitizeAddressRequest(AddressRequest request) {
        request.setCity(StringEscapeUtils.escapeHtml4(request.getCity()));
        request.setStreet(StringEscapeUtils.escapeHtml4(request.getStreet()));
        request.setState(StringEscapeUtils.escapeHtml4(request.getState()));
        request.setCountry(StringEscapeUtils.escapeHtml4(request.getCountry()));
    }

}
