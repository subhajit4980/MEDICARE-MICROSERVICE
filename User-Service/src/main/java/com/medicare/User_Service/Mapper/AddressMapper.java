package com.medicare.User_Service.Mapper;

import com.medicare.User_Service.Config.MapStructConfig;
import com.medicare.User_Service.DTO.Request.AddressRequest;
import com.medicare.User_Service.Model.Address;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

@Mapper(config = MapStructConfig.class)
public interface AddressMapper {

    @Mapping(target = "addressId", ignore = true)
    @Mapping(target = "userId", ignore = true)
    @Mapping(target = "defaultAddress", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    Address toEntity(AddressRequest request);

    @Mapping(target = "addressId", ignore = true)
    @Mapping(target = "userId", ignore = true)
    @Mapping(target = "defaultAddress", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    void updateFromRequest(AddressRequest request, @MappingTarget Address address);
}
