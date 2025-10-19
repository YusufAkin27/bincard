package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusCardNotFoundException extends BusinessException {
    public BusCardNotFoundException() {
        super("Otobüs kartı bulunamadı!");
    }
}
