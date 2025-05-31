package akin.city_card.user.exceptions;

import akin.city_card.security.exception.BusinessException;

public class FileFormatCouldNotException extends BusinessException {
    public FileFormatCouldNotException() {
        super("Desteklenmeyen dosya formatı ");
    }
}
