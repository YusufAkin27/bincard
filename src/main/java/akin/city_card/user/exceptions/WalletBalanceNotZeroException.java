package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class WalletBalanceNotZeroException extends BusinessException {
    public WalletBalanceNotZeroException() {
        super("Hesabınızı silebilmek için cüzdan bakiyenizin sıfır (0) olması gerekmektedir.");
    }
}
