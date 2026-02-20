package com.medicare.User_Service.DTO.Response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class MessageResponse {
    private String message;
    private Object response;
}