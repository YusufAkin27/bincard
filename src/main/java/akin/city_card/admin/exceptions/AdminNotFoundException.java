package akin.city_card.admin.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AdminNotFoundException extends BusinessException {
    public AdminNotFoundException() {
        super("Admin bulunamadı");
    }
}
