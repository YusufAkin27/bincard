package akin.city_card.validations;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.stereotype.Component;

@Component
public class TelephoneValidator implements ConstraintValidator<ValidTelephone, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) {
            return true;
        }

        String digitsOnly = value.replaceAll("[^0-9]", "");

        if (digitsOnly.matches("5\\d{9}")) {
            return true;
        }

        if (digitsOnly.matches("0?5\\d{9}")) {
            return true;
        }

        if (digitsOnly.matches("90?5\\d{9}")) {
            return true;
        }

        return false;
    }

}
