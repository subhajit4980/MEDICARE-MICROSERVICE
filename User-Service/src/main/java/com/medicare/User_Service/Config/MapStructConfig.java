package com.medicare.User_Service.Config;

import org.mapstruct.MapperConfig;
import org.mapstruct.ReportingPolicy;

/**
 * Central MapStruct configuration for User-Service.
 * All mappers can reference this config for consistent behaviour.
 */
@MapperConfig(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE,
        unmappedSourcePolicy = ReportingPolicy.IGNORE
)
public interface MapStructConfig {
}
