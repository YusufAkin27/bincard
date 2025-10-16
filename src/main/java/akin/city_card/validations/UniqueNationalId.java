package akin.city_card.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = UniqueNationalIdValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface UniqueNationalId {
    String message() default "Bu TC Kimlik numarası zaten kayıtlı";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
