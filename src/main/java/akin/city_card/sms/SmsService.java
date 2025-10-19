package akin.city_card.sms;


import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SmsService {

    private final TwilioProperties properties;

    public void sendSms(SmsRequest request) {
        Message.creator(
                new PhoneNumber(request.getTo()),
                new PhoneNumber(properties.getPhoneNumber()),
                request.getMessage()
        ).create();
    }
}
