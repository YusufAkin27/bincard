package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class VideoSizeLargerException extends BusinessException {
    public VideoSizeLargerException() {
        super("Video Size Larger Exception");
    }
}
