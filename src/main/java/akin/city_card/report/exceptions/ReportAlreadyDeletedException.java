package akin.city_card.report.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ReportAlreadyDeletedException extends BusinessException {
    public ReportAlreadyDeletedException() {
        super("Rapor zaten silinmiş");
    }
}
