package akin.city_card.security.exception;

public class AccountFrozenException extends BusinessException {
    public AccountFrozenException() {
        super("Hesap Aktif Değil");
    }
}
