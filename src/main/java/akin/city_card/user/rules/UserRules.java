package akin.city_card.user.rules;

import akin.city_card.user.exceptions.*;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.Period;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

@Service
public class UserRules {

    private final UserRepository userRepository;

    @Autowired
    public UserRules(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // ➤ Yaş kontrolü
    public void checkUserIsAtLeast18YearsOld(User user) throws BirthDateRequiredException, UnderageUserException {
        if (user.getBirthDate() == null) {
            throw new BirthDateRequiredException();
        }

        int age = Period.between(user.getBirthDate(), LocalDate.now()).getYears();
        if (age < 18) {
            throw new UnderageUserException();
        }
    }

    // ➤ E-posta kontrolü (zorunlu + benzersizlik + format)
    public void checkEmailIsUnique(String email) throws EmailAlreadyExistsException, EmailRequiredException, InvalidEmailFormatException {
        if (email == null || email.isBlank()) {
            throw new EmailRequiredException();
        }

        if (!isValidEmailFormat(email)) {
            throw new InvalidEmailFormatException();
        }

        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException();
        }
    }

    // ➤ Telefon kontrolü (zorunlu + benzersizlik + format)
    public void checkPhoneIsUnique(String phoneNumber) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException, InvalidPhoneNumberFormatException {
        if (phoneNumber == null || phoneNumber.isBlank()) {
            throw new PhoneNumberRequiredException();
        }

        if (!isValidTurkishPhoneFormat(phoneNumber)) {
            throw new InvalidPhoneNumberFormatException();
        }

        if (userRepository.existsByUserNumber(phoneNumber)) {
            throw new PhoneNumberAlreadyExistsException();
        }
    }

    // ➤ T.C. Kimlik No kontrolü (zorunlu + benzersizlik + algoritmik doğrulama)
    public void checkNationalIdIsUnique(String nationalId) throws NationalIdAlreadyExistsException, NationalIdRequiredException, InvalidNationalIdFormatException {
        if (nationalId == null || nationalId.isBlank()) {
            throw new NationalIdRequiredException();
        }

        if (!isValidTurkishNationalId(nationalId)) {
            throw new InvalidNationalIdFormatException();
        }

        if (userRepository.existsByNationalId(nationalId)) {
            throw new NationalIdAlreadyExistsException();
        }
    }

    // ✳ Email regex kontrolü (sade kontrol)
    private boolean isValidEmailFormat(String email) {
        String emailRegex = "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,}$";
        return Pattern.matches(emailRegex, email);
    }

    // ✳ Telefon no kontrolü: +905xxxxxxxxx veya 05xxxxxxxxx (zorunlu olarak 11 veya 13 haneli)
    private boolean isValidTurkishPhoneFormat(String phone) {
        return phone.matches("^((\\+90)|0)?5\\d{9}$");
    }

    // ✳ T.C. Kimlik No kontrolü (11 haneli ve son basamak algoritması)
    private boolean isValidTurkishNationalId(String nationalId) {
        if (!nationalId.matches("^\\d{11}$")) return false;

        int[] digits = nationalId.chars().map(c -> c - '0').toArray();

        int sumOdd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8];
        int sumEven = digits[1] + digits[3] + digits[5] + digits[7];

        int digit10 = ((sumOdd * 7) - sumEven) % 10;
        int digit11 = (IntStream.range(0, 10).map(i -> digits[i]).sum()) % 10;

        return digits[9] == digit10 && digits[10] == digit11;
    }
}
