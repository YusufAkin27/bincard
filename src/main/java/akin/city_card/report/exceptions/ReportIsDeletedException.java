package akin.city_card.report.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ReportIsDeletedException extends BusinessException {
    public ReportIsDeletedException() {
        super("Rapor silinmiş");
    }
}
