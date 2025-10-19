package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class UnauthorizedLocationUpdateException extends BusinessException {
    public UnauthorizedLocationUpdateException(String requestIp) {
        super("Bu IP adresinden konum güncelleme izni yok: " + requestIp);
    }
}
