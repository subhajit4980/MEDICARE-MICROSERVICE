package com.medicare.User_Service.Service;

import com.medicare.User_Service.Models.Address;
import com.medicare.User_Service.Payload.Request.AddressRequest;
import com.medicare.User_Service.Payload.Response.MessageResponse;
import jakarta.validation.Valid;

import java.util.List;

public interface UserService {
    MessageResponse addAddresses(AddressRequest addressRequest);
    MessageResponse updateAddress(Address addressRequest);
    List<Address> getAddress( String userId);

}
