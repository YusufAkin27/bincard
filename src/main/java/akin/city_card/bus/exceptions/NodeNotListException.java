package akin.city_card.bus.exceptions;

import akin.city_card.security.exception.BusinessException;

public class NodeNotListException extends BusinessException {
    public NodeNotListException() {
        super("Rotada duraklar bulunamadı");
    }
}
