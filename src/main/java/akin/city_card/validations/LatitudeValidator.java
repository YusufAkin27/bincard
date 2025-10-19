package akin.city_card.validations;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class LatitudeValidator implements ConstraintValidator<ValidLatitude, Double> {

    @Override
    public boolean isValid(Double value, ConstraintValidatorContext context) {
        if (value == null) return false; // @NotNull ile birlikte kullanılması daha iyi olur
        return value >= -90 && value <= 90;
    }
}