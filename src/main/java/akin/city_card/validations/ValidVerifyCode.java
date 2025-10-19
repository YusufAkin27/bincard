package akin.city_card.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = VerifyCodeValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidVerifyCode {
    String message() default "Doğrulama kodu 6 rakamdan oluşmalıdır";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
