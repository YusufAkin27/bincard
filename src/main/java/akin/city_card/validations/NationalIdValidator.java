package akin.city_card.validations;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class NationalIdValidator implements ConstraintValidator<ValidNationalId, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || !value.matches("^\\d{11}$")) {
            return false;
        }

        if (value.charAt(0) == '0') {
            return false; // TC kimlik numarası 0 ile başlayamaz
        }

        int[] digits = value.chars().map(c -> c - '0').toArray();

        int sumOdd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8];
        int sumEven = digits[1] + digits[3] + digits[5] + digits[7];

        int tenthDigit = ((sumOdd * 7) - sumEven) % 10;
        int eleventhDigit = (java.util.Arrays.stream(digits, 0, 10).sum()) % 10;

        return digits[9] == tenthDigit && digits[10] == eleventhDigit;
    }

}
