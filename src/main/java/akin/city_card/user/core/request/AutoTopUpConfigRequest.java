package akin.city_card.user.core.request;

import akin.city_card.buscard.model.BusCard;

import akin.city_card.user.model.User;

import lombok.Data;

@Data
public class AutoTopUpConfigRequest {

    private Long busCard;

    private double threshold;

    private double amount;

}
