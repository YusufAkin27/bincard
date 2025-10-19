package akin.city_card.validations;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class LongitudeValidator implements ConstraintValidator<ValidLongitude, Double> {

    @Override
    public boolean isValid(Double value, ConstraintValidatorContext context) {
        if (value == null) return false; // @NotNull ile birlikte kullan
        return value >= -180 && value <= 180;
    }
}
