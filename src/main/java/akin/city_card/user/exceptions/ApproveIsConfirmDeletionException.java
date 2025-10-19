package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class ApproveIsConfirmDeletionException extends BusinessException {
    public ApproveIsConfirmDeletionException() {
        super("Hesap silmek için işlemi onaylamanız gerekiyor");
    }
}
