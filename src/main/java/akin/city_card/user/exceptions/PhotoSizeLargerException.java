package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class PhotoSizeLargerException extends BusinessException {
    public PhotoSizeLargerException() {
        super("Photo size larger than maximum allowed");
    }
}
