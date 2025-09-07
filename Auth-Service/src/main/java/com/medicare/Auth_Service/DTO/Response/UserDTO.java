package com.medicare.Auth_Service.DTO.Response;

import com.medicare.Auth_Service.Model.Enum.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {
    private String userId;
    private String firstName;
    private String lastName;
    private String email;
    private Boolean verified;
    private Role role;
}
