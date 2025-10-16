package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class OnlyPhotosAndVideosException extends BusinessException {
    public OnlyPhotosAndVideosException() {
        super("Only photos and videos can be found");
    }
}
