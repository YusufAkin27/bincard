package akin.city_card.report.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ReportNotFoundException extends BusinessException {
    public ReportNotFoundException() {
        super("Rapor Bulunamadı");
    }
}
