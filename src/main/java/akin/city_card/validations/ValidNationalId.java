package akin.city_card.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = NationalIdValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidNationalId {
    String message() default "Geçersiz TC Kimlik Numarası";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
