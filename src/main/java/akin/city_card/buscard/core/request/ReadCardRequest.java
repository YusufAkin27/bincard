package akin.city_card.buscard.core.request;

import lombok.Data;

@Data
public class ReadCardRequest {
private String uid;
private Integer txCounter;
}
