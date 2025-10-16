package akin.city_card.buscard.exceptions;

import akin.city_card.security.exception.BusinessException;

public class InvalidTopUpAmountException extends BusinessException {
    public InvalidTopUpAmountException() {
        super("Yükleme tutarı 0 veya negatif olamaz!");
    }
}