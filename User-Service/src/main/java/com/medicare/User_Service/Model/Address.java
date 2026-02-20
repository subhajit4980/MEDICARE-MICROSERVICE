package com.medicare.User_Service.Model;

import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
@Document(collection = "addresses")
public class Address {
    @Id
    private String addressId;
    @NotBlank
    private String userId; // Reference to the user
    @NotBlank
    private String name; // Name associated with the address (e.g., John Doe)
    @NotBlank
    private String BuildingNumber;
    @NotBlank
    private String street; // Street address
    @NotBlank
    private String landMark; // nearest landmark
    @NotBlank
    private String city; // City
    @NotBlank
    private String state; // State or Province
    @NotBlank
    private String postalCode; // Postal code
    @NotBlank
    private String country; // Country
    @NotBlank
    private String phone; // Phone number
    @NotBlank
    private String label;
    @NotBlank
    private boolean isDefault;
}
