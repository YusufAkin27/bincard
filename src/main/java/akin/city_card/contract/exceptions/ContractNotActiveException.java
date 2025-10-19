package akin.city_card.contract.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ContractNotActiveException extends BusinessException {
    public ContractNotActiveException() {
        super("Sözleşme aktif değil");
    }
}
