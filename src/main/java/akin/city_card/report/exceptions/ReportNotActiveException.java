package akin.city_card.report.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ReportNotActiveException extends BusinessException {
    public ReportNotActiveException() {
        super("Aktif olmayan rapor silinemez");
    }
}
