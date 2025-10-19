package akin.city_card.report.exceptions;

import akin.city_card.security.exception.BusinessException;

public class SatisfactionAlreadyRatedException extends BusinessException {
    public SatisfactionAlreadyRatedException() {
        super("Bu şikayet için zaten memnuniyet puanı verilmiş");
    }
}
