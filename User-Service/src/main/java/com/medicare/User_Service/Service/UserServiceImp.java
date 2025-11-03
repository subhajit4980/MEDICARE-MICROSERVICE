package com.medicare.User_Service.Service;

import com.medicare.User_Service.Exception.UserException;
import com.medicare.User_Service.Models.Address;
import com.medicare.User_Service.Payload.Request.AddressRequest;
import com.medicare.User_Service.Payload.Response.MessageResponse;
import com.medicare.User_Service.Repository.AddressRepository;
import org.apache.commons.text.StringEscapeUtils;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import java.util.List;

@RequiredArgsConstructor
public class UserServiceImp implements UserService {
    private static final Logger log = LoggerFactory.getLogger(UserServiceImp.class);
    ModelMapper modelMapper = new ModelMapper();
    private final AddressRepository addressRepository;

    @Override
    public MessageResponse addAddresses(AddressRequest addressRequest) {
        try {
            // 1. Validate input
            if (addressRequest == null || addressRequest.getUserId() == null) {
                throw new UserException(HttpStatus.BAD_REQUEST, "Invalid address request");
            }

            // 2. Sanitize input (prevent injection or unwanted data)
            sanitizeAddressRequest(addressRequest);

            // 3. Map DTO → Entity
            Address newAddress = modelMapper.map(addressRequest, Address.class);
            newAddress.setDefault(false);

            // 4. Save securely
            addressRepository.save(newAddress);

            // 5. Return success message
            return new MessageResponse("Address added successfully");

        } catch (UserException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error adding address for user: {}", e.getMessage(), e);
            throw new UserException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to add address");
        }
    }

    @Override
    public MessageResponse updateAddress(Address addressRequest) {
        return null;
    }

    @Override
    public List<Address> getAddress(String userId) {
        return null;
    }

    private void sanitizeAddressRequest(AddressRequest request) {
        request.setCity(StringEscapeUtils.escapeHtml4(request.getCity()));
        request.setStreet(StringEscapeUtils.escapeHtml4(request.getStreet()));
        request.setState(StringEscapeUtils.escapeHtml4(request.getState()));
        request.setCountry(StringEscapeUtils.escapeHtml4(request.getCountry()));
    }

}
