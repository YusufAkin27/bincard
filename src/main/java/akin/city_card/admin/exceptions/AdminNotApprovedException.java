package akin.city_card.admin.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AdminNotApprovedException extends BusinessException {
    public AdminNotApprovedException() {
        super("Admin Süper admin tarafından onaylanmamış");
    }
}
