package com.medicare.User_Service.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medicare.User_Service.Models.Address;
import com.medicare.User_Service.Payload.Request.AddressRequest;
import com.medicare.User_Service.Payload.Response.MessageResponse;
import com.medicare.User_Service.Repository.AddressRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;

import java.util.List;
@RequiredArgsConstructor
public class UserService {

    ModelMapper modelMapper = new ModelMapper();
    private final AddressRepository addressRepository;
    public MessageResponse addAddresses(AddressRequest addressRequest) {
        try{
            Address newAddress=modelMapper.map(addressRequest,Address.class);
            newAddress.setDefault(false);
            addressRepository.save(newAddress);
            return new MessageResponse("Address added successfully");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public MessageResponse updateAddress(@Valid Address addressRequest) {
        return null;
    }

    public List<Address> getAddress(@Valid String userId) {
        return null;
    }
}
