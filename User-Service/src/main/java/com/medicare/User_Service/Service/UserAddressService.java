package com.medicare.User_Service.Service;

import com.medicare.User_Service.Model.Address;
import com.medicare.User_Service.DTO.Request.AddressRequest;
import com.medicare.User_Service.DTO.Response.MessageResponse;

import java.util.List;

public interface UserAddressService {
    MessageResponse addAddresses( String userId, AddressRequest addressRequest);
    MessageResponse updateAddress( String userId, String addressId, AddressRequest addressRequest);
    List<Address> getAddress( String userId);
    Address getAddressById(String userId, String addressId);
    MessageResponse deleteAddress(String userId, String addressId);

}
