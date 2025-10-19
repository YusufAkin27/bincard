package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class DuplicateBusPlateException extends BusinessException {
    public DuplicateBusPlateException() {
        super("Plaka numarası benzersiz olmalı");
    }
}
