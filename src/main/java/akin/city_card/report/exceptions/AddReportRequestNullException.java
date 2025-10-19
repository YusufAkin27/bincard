package akin.city_card.report.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AddReportRequestNullException extends BusinessException {
    public AddReportRequestNullException() {
        super("Report Request boş");
    }
}
