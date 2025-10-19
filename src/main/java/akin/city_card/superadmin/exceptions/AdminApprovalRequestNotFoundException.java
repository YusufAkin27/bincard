package akin.city_card.superadmin.exceptions;

import akin.city_card.security.exception.BusinessException;

public class AdminApprovalRequestNotFoundException extends BusinessException {
    public AdminApprovalRequestNotFoundException() {
        super(" admin approval request not found");
    }
}
