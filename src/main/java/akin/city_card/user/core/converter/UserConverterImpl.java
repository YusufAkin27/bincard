package akin.city_card.user.core.converter;

import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.AutoTopUpConfigDTO;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.core.response.UserExportDTO;
import akin.city_card.user.model.AutoTopUpConfig;
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

    @Override
    public UserExportDTO convertUserToExportDTO(User user) {
        if (user == null) return null;

        UserExportDTO dto = new UserExportDTO();
        dto.setId(user.getId());
        dto.setUserNumber(user.getUserNumber());
        dto.setNationalId(user.getNationalId());
        dto.setBirthDate(user.getBirthDate());
        dto.setWalletActivated(user.isWalletActivated());
        dto.setAllowNegativeBalance(user.isAllowNegativeBalance());
        dto.setNegativeBalanceLimit(user.getNegativeBalanceLimit());
        dto.setAutoTopUpEnabled(user.isAutoTopUpEnabled());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());

        // profileInfo embedded ise null kontrolü yapıp ekleyebilirsin
        if (user.getProfileInfo() != null) {
            dto.setFullName(user.getProfileInfo().getName()+" "+user.getProfileInfo().getSurname());
            dto.setEmail(user.getProfileInfo().getEmail());
        }

        return dto;
    }



}
