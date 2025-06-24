package akin.city_card.user.core.converter;

import akin.city_card.security.entity.Role;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.model.User;
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
                .surname(request.getLastName())//+90 ile başlıcak
                .userNumber(request.getTelephone()) // username olarak kullanılacak
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Collections.singleton(Role.USER)) // Varsayılan kullanıcı rolü
                .active(false) // Henüz doğrulanmadı
                .allowNegativeBalance(false)
                .negativeBalanceLimit(0.0)
                .emailVerified(false)
                .walletActivated(false)
                .autoTopUpEnabled(false)
                .phoneVerified(false)
                .ipAddress(request.getIpAddress()) // Mobil uygulamadan gelen
                .deviceUuid(request.getDeviceUuid())
                .fcmToken(request.getFcmToken())
                .build();
    }
    @Override
    public UserDTO convertUserToDTO(User user) {
        return UserDTO.builder()
                .name(user.getName())
                .surname(user.getSurname())
                .email(user.getEmail())
                .phoneNumber(user.getUserNumber())

                .phoneVerified(user.isPhoneVerified())
                .emailVerified(user.isEmailVerified())

                .profilePicture(user.getProfilePicture())

                .nationalId(user.getNationalId())
                .birthDate(user.getBirthDate())
                .walletActivated(user.isWalletActivated())

                .allowNegativeBalance(user.isAllowNegativeBalance())
                .negativeBalanceLimit(user.getNegativeBalanceLimit())
                .autoTopUpEnabled(user.isAutoTopUpEnabled())

                .notificationPreferences(user.getNotificationPreferences())
                .build();
    }

}
