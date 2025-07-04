package akin.city_card.bus.exceptions;

import akin.city_card.bus.model.Bus;
import akin.city_card.security.exception.BusinessException;

public class UnauthorizedAccessException extends BusinessException {
    public UnauthorizedAccessException( ) {
        super("Sadece adminler konum geçmişini görebilir.");
    }
}
