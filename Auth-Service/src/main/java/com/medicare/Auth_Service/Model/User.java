package com.medicare.Auth_Service.Model;

import com.medicare.Auth_Service.Model.Enum.Role;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Document(collection = "users") // Collection name in MongoDB
public class User{
    @Id
    private String userId;

    @NotBlank
    private String firstName;

    @NotBlank
    private String lastName;

    @NotBlank
    @Size(max = 50)
    private String email;
    @Size(min = 8)
    private String password;
    @NotBlank
    private Boolean verified =false;

    @NotBlank
    private Date creationDate =new Date();

    private String GoogleSub;

    @Enumerated(EnumType.STRING)
    private Role role;
}