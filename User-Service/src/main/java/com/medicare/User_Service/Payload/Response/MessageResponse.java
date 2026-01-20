package com.medicare.User_Service.Payload.Response;

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