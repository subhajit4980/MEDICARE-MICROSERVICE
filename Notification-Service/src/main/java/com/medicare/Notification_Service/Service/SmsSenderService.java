package com.medicare.Notification_Service.Service;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.MessageAttributeValue;
import software.amazon.awssdk.services.sns.model.PublishRequest;
import software.amazon.awssdk.services.sns.model.PublishResponse;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Profile("prod")
public class SmsSenderService implements SmsSender {

    private final SnsClient snsClient;

    @Override
    public String sendSms(String phoneNumber, String message) {

        PublishRequest request = PublishRequest.builder()
                .phoneNumber(phoneNumber)
                .message(message)
                .messageAttributes(Map.of(
                        "AWS.SNS.SMS.SMSType",
                        MessageAttributeValue.builder().stringValue("Transactional").dataType("String").build()
                ))
                .build();


        PublishResponse response = snsClient.publish(request);
        System.out.println(response.messageId());
        return response.messageId(); // AWS assigns a messageId for tracking
    }
}
