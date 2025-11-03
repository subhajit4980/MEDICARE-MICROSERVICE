package com.medicare.User_Service.Repository;

import com.medicare.User_Service.Models.Address;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface AddressRepository extends MongoRepository<Address, Integer> {
    Optional<Address> findByUserId(String userId);
    Optional<Address> findByAddressId(String addressId);
}