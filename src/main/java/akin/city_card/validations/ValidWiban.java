package akin.city_card.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = WibanValidator.class)
@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidWiban {
    String message() default "Geçersiz WIBAN formatı";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
