package com.medicare.User_Service.Repository;

import com.medicare.User_Service.Models.Address;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
@Repository
public interface AddressRepository extends MongoRepository<Address, String> {
    Optional<List<Address>> findByUserId(String userId);
    Optional<Address> findByAddressId(String addressId);
}