package com.medicare.Auth_Service.Model;

import com.medicare.Auth_Service.Model.Enum.Role;
import com.medicare.Auth_Service.Model.Enum.UserStatus;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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
@Document(collection = "Users") // Collection name in MongoDB
public class User {
    @Id
    private String userId;

    @NotBlank
    @Size(max = 50)
    private String email;

    @Size(min = 8)
    private String password;

    @NotNull
    private Boolean verified = false;

    @NotNull
    private Date creationDate = new Date();

    private String googleSub;

    @Enumerated(EnumType.STRING)
    private Role role = Role.USER;

    @NotNull
    @Enumerated(EnumType.STRING)
    private UserStatus status = UserStatus.ACTIVE;

}