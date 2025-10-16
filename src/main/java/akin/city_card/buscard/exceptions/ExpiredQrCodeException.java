package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ExpiredQrCodeException extends BusinessException {
    public ExpiredQrCodeException() {
        super("qr kodun süresi dolmuş");
    }
}
