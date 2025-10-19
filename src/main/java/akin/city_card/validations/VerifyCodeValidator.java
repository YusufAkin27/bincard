package akin.city_card.validations;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class VerifyCodeValidator implements ConstraintValidator<ValidVerifyCode, String> {

    @Override
    public boolean isValid(String code, ConstraintValidatorContext context) {
        if (code == null) return false;
        return code.matches("\\d{6}");
    }
}
