package akin.city_card.contract.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ContractNotFoundException extends BusinessException {
    public ContractNotFoundException() {
        super("Sözleşme bulunamadı");
    }
}
