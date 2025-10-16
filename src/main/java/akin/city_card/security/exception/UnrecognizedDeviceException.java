package akin.city_card.security.exception;

public class UnrecognizedDeviceException extends BusinessException {
    public UnrecognizedDeviceException() {
        super("Yeni cihaz algılandı. Giriş için doğrulama kodu gönderildi.");
    }
}
