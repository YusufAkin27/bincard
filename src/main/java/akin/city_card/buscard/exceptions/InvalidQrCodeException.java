package akin.city_card.buscard.exceptions;

public class InvalidQrCodeException extends RuntimeException {
    public InvalidQrCodeException() {
        super("qr kod tanımlanamadı");
    }
}
