package akin.city_card.validations;

import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.user.service.concretes.PhoneNumberFormatter;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UniquePhoneNumberValidator implements ConstraintValidator<UniquePhoneNumber, String> {

    private final SecurityUserRepository securityUserRepository;

    @Override
    public boolean isValid(String phoneNumber, ConstraintValidatorContext context) {
        if (phoneNumber == null || phoneNumber.isBlank()) {
            return true; // boş kontrolü @NotBlank ile yapılmalı
        }

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(phoneNumber);
        if (normalizedPhone == null) return false;

        return securityUserRepository.findByUserNumber(normalizedPhone)
                .map(SecurityUser::isEnabled)
                .map(isEnabled -> !isEnabled)
                .orElse(true);
    }

}
