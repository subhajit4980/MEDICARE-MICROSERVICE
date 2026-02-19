package com.medicare.Auth_Service.Events;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRegisteredEvent {
    String userId;
    @NotBlank
    @Size(max = 50)
    String email;
    String firstName;
    String lastName;

}
