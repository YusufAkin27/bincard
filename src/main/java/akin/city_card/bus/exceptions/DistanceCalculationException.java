package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class DistanceCalculationException extends BusinessException {
    public DistanceCalculationException() {
        super("mesafe hesaplanırken hata oldu");
    }
}
