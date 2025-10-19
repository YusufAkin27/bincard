package akin.city_card.contract.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AlreadyContractRejectedException extends BusinessException {
    public AlreadyContractRejectedException() {
        super("Sözleşme zaten reddedildi");
    }
}
