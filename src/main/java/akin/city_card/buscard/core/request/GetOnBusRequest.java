package akin.city_card.buscard.core.request;

import lombok.Data;

@Data
public class GetOnBusRequest {
    private String uid;
    private String validatorId;
}
