package com.medicare.User_Service.DTO.Response;

import com.medicare.User_Service.Model.Address;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserSummaryResponse {
    private String userId;
    private String firstName;
    private String lastName;
    private String profileImageUrl;

    private String language;
    private String timeZone;
    private String preferredCurrency;
    private Boolean marketingOptIn;

    private Address defaultAddress;
}

