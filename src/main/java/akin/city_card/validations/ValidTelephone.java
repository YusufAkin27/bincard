package akin.city_card.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = TelephoneValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidTelephone {
    String message() default "Geçersiz telefon numarası";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
