package com.medicare.Notification_Service.Service;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;
import software.amazon.awssdk.services.sns.model.PublishResponse;

@Service
@RequiredArgsConstructor
@Profile("prod")
public class SmsSenderService implements SmsSender {

    private final SnsClient snsClient;

    @Override
    public String sendSms(String phoneNumber, String message) {

        PublishRequest request = PublishRequest.builder()
                .message(message)
                .phoneNumber(phoneNumber)
                .build();

        PublishResponse response = snsClient.publish(request);
        System.out.println(response.messageId());
        return response.messageId(); // AWS assigns a messageId for tracking
    }
}
