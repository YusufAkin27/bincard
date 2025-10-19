package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AlreadyWalletUserException extends BusinessException {
    public AlreadyWalletUserException() {
        super("Kullanıcının zaten bir cüzdanı var");
    }
}
