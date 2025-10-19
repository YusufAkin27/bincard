package akin.city_card.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = EmailValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidEmail {
    String message() default "Geçersiz email formatı";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
