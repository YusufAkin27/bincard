package akin.city_card.security.exception;

public class PhoneNotVerifiedException extends BusinessException {
    public PhoneNotVerifiedException() {
        super("Telefon doğrulanmamış. Doğrulama kodu gönderildi.");
    }
}
