package akin.city_card.contract.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ContractAlreadyAcceptedException extends BusinessException {
    public ContractAlreadyAcceptedException() {
        super("Sözleşme zaten kabul edildi");
    }
}
