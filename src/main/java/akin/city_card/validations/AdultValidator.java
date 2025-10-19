package akin.city_card.validations;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.time.LocalDate;
import java.time.Period;

public class AdultValidator implements ConstraintValidator<Adult, LocalDate> {

    private static final int MIN_AGE = 18;

    @Override
    public boolean isValid(LocalDate birthDate, ConstraintValidatorContext context) {
        if (birthDate == null) return false;

        LocalDate today = LocalDate.now();
        Period age = Period.between(birthDate, today);

        return age.getYears() >= MIN_AGE;
    }
}
