package akin.city_card.wallet.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AdminOrSuperAdminNotFoundException extends BusinessException {
    public AdminOrSuperAdminNotFoundException() {
        super("Admin veya super admin bulunamadı");
    }
}
