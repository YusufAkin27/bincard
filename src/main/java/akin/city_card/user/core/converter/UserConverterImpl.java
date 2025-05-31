package akin.city_card.user.core.converter;

import akin.city_card.security.entity.Role;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.model.User;
import akin.city_card.security.entity.SecurityUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
@RequiredArgsConstructor
public class UserConverterImpl implements UserConverter {

    private final PasswordEncoder passwordEncoder;



    @Override
    public User convertUserToCreateUser(CreateUserRequest request) {
        return User.builder()
                .name(request.getFirstName())
                .surname(request.getLastName())
                .userNumber(request.getTelephone()) // Doğru alan adı: userNumber
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Collections.singleton(Role.USER)) // default olarak USER atanıyor
                .active(true)
                .phoneVerified(false)
                .build();
    }
}
