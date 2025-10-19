package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AlreadyBusCardLowBalanceException extends BusinessException {
    public AlreadyBusCardLowBalanceException() {
        super("bu kart zaten düşük bakiye uyarısında var");
    }
}
