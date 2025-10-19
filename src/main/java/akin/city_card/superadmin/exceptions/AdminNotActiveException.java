package akin.city_card.superadmin.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AdminNotActiveException extends BusinessException {
    public AdminNotActiveException() {
        super("Admin aktif değil");
    }
}
