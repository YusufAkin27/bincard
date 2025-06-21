package akin.city_card.user.rules;


import akin.city_card.user.exceptions.*;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.Period;

@Service
public class UserRules {

    private final UserRepository userRepository;

    @Autowired
    public UserRules(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void checkUserIsAtLeast18YearsOld(User user) throws BirthDateRequiredException, UnderageUserException {
        if (user.getBirthDate() == null) {
            throw new BirthDateRequiredException();
        }

        int age = Period.between(user.getBirthDate(), LocalDate.now()).getYears();
        if (age < 18) {
            throw new UnderageUserException();
        }
    }

    public void checkEmailIsUnique(String email) throws EmailAlreadyExistsException, EmailRequiredException {
        if (email == null || email.isBlank()) {
            throw new EmailRequiredException();
        }

        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException();
        }
    }

    public void checkPhoneIsUnique(String phoneNumber) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException {
        if (phoneNumber == null || phoneNumber.isBlank()) {
            throw new PhoneNumberRequiredException();
        }

        if (userRepository.existsByPhoneNumber(phoneNumber)) {
            throw new PhoneNumberAlreadyExistsException();
        }
    }

    public void checkNationalIdIsUnique(String nationalId) throws NationalIdAlreadyExistsException, NationalIdRequiredException {
        if (nationalId == null || nationalId.isBlank()) {
            throw new  NationalIdRequiredException();
        }

        if (userRepository.existsByNationalId(nationalId)) {
            throw new NationalIdAlreadyExistsException();
        }
    }
}
