package akin.city_card.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = LatitudeValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidLatitude {
    String message() default "Geçersiz enlem değeri (Latitude -90 ile +90 arasında olmalı)";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
