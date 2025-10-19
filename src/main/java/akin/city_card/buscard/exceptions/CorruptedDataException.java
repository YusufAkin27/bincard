package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class CorruptedDataException extends BusinessException {
    public CorruptedDataException( ) {
        super("Kart işlem sayacı bozuk! kart kopyalama tespit edildi");
    }
}
