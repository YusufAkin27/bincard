package akin.city_card.user.core.converter;

import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.ProfileInfo;
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
        ProfileInfo profileInfo = ProfileInfo.builder()
                .name(request.getFirstName())
                .surname(request.getLastName())
                .build();
        DeviceInfo deviceInfo = DeviceInfo.builder()
                .deviceUuid(request.getDeviceUuid())
                .ipAddress(request.getIpAddress())
                .fcmToken(request.getFcmToken())
                .build();
        return User.builder()
                .userNumber(request.getTelephone())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Collections.singleton(Role.USER))
                .isActive(false)
                .allowNegativeBalance(false)
                .negativeBalanceLimit(0.0)
                .emailVerified(false)
                .walletActivated(false)
                .autoTopUpEnabled(false)
                .phoneVerified(false)
                .profileInfo(profileInfo)
                .deviceInfo(deviceInfo)
                .build();
    }

    @Override
    public UserDTO convertUserToDTO(User user) {
        ProfileInfo profile = user.getProfileInfo();

        return UserDTO.builder()
                .name(profile != null ? profile.getName() : null)
                .surname(profile != null ? profile.getSurname() : null)
                .email(profile != null ? profile.getEmail() : null)
                .phoneNumber(user.getUserNumber())

                .phoneVerified(user.isPhoneVerified())
                .emailVerified(user.isEmailVerified())

                .profilePicture(profile != null ? profile.getProfilePicture() : null)

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
