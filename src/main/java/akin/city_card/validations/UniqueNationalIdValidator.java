package akin.city_card.validations;

import akin.city_card.user.repository.UserRepository;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class UniqueNationalIdValidator implements ConstraintValidator<UniqueNationalId, String> {


    private final UserRepository userRepository;

    @Override
    public boolean isValid(String nationalId, ConstraintValidatorContext context) {
        if (nationalId == null || nationalId.isBlank()) {
            return true;
        }
        return !userRepository.existsByIdentityInfo_NationalId(nationalId);
    }
}
