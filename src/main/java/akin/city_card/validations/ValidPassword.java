package akin.city_card.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PasswordValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPassword {
    String message() default "Şifre 6 karakterden oluşmalı ve sadece rakamlardan ibaret olmalıdır";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
