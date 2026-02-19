package com.medicare.User_Service.Payload.Request;

import lombok.Data;

import java.util.Date;
@Data
public class ProfileRequest {
    private String userId;
    private String firstName;
    private String lastName;
    private Date dateOfBirth;
    private String profileImageUrl;
}
