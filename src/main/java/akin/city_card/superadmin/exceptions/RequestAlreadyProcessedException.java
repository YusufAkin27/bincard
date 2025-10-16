package akin.city_card.superadmin.exceptions;

import akin.city_card.security.exception.BusinessException;

public class RequestAlreadyProcessedException extends BusinessException {
    public RequestAlreadyProcessedException() {
        super("Request already processed");
    }
}
