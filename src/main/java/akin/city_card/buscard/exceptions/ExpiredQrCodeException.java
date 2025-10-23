package akin.city_card.buscard.exceptions;

public class ExpiredQrCodeException extends RuntimeException {
    public ExpiredQrCodeException() {
        super("qr kodun süresi dolmuş");
    }
}
