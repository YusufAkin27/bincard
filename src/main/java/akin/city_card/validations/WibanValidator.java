package akin.city_card.validations;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class WibanValidator implements ConstraintValidator<ValidWiban, String> {

    private static final String WIBAN_REGEX = "^WBN-\\d{16}$";

    @Override
    public boolean isValid(String wiban, ConstraintValidatorContext context) {
        if (wiban == null || wiban.isBlank()) {
            return false; // Zorunlu alan ise boş olmamalı
        }
        return wiban.matches(WIBAN_REGEX);
    }
}
