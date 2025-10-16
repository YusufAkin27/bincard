package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class WalletDeactivationException extends BusinessException {
    public WalletDeactivationException() {
        super("Bakiyesi olan cüzdan pasif yapılamaz. Önce bakiyeyi boşaltın.");
    }
}
