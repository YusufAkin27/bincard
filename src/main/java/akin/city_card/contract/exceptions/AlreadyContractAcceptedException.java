package akin.city_card.contract.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AlreadyContractAcceptedException extends BusinessException {
    public AlreadyContractAcceptedException() {
        super("Sözleşme zaten onaylanmış");
    }
}
