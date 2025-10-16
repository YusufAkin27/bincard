package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidQrCodeException extends BusinessException {
    public InvalidQrCodeException() {
        super("qr kod tanımlanamadı");
    }
}
