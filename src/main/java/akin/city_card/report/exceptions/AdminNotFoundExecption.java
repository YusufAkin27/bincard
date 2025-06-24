package akin.city_card.report.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AdminNotFoundExecption extends BusinessException {

    public AdminNotFoundExecption() {
        super("Admin kullanıcısı bulunamadı.");
    }
}
