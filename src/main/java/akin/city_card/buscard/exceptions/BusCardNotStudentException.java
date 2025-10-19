package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class BusCardNotStudentException extends BusinessException {
    public BusCardNotStudentException( ) {
        super("Bu kart öğrenci kartı değil");
    }
}
