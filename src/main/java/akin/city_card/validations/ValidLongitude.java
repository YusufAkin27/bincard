package akin.city_card.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = LongitudeValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidLongitude {
    String message() default "Geçersiz boylam değeri (Longitude -180 ile +180 arasında olmalı)";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
