package akin.city_card.user.core.converter;

import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.UserExportDTO;
import akin.city_card.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class UserConverterImpl implements UserConverter {

    private final PasswordEncoder passwordEncoder;

    @Override
    public CacheUserDTO toCacheUserDTO(User user) {
        return CacheUserDTO.builder()
                .id(user.getId())
                .userNumber(user.getUserNumber())

                // Profile Info
                .name(user.getProfileInfo() != null ? user.getProfileInfo().getName() : null)
                .surname(user.getProfileInfo() != null ? user.getProfileInfo().getSurname() : null)
                .email(user.getProfileInfo() != null ? user.getProfileInfo().getEmail() : null)
                .profilePicture(user.getProfileInfo() != null ? user.getProfileInfo().getProfilePicture() : null)
                .active(user.isActive())
                .deleted(user.isDeleted())
                .password(user.getPassword())
                // Device Info
                .fcmToken(user.getDeviceInfo() != null ? user.getDeviceInfo().getFcmToken() : null)
                .deviceUuid(user.getDeviceInfo() != null ? user.getDeviceInfo().getDeviceUuid() : null)
                .phoneNumber(user.getDeviceInfo() != null ? user.getDeviceInfo().getIpAddress() : null) // eğer farklı alan kullanıyorsan değiştir

                .phoneVerified(user.isPhoneVerified())
                .emailVerified(user.isEmailVerified())
                .birthDate(user.getBirthDate())
                .nationalId(user.getNationalId())

                .walletActivated(user.isWalletActivated())
                .allowNegativeBalance(user.isAllowNegativeBalance())
                .negativeBalanceLimit(user.getNegativeBalanceLimit())
                .autoTopUpEnabled(user.isAutoTopUpEnabled())

                .roles(user.getRoles().stream().map(Enum::name).collect(Collectors.toSet()))

                // Notification Preferences
                .pushEnabled(user.getNotificationPreferences() != null && user.getNotificationPreferences().isPushEnabled())
                .smsEnabled(user.getNotificationPreferences() != null && user.getNotificationPreferences().isSmsEnabled())
                .emailEnabled(user.getNotificationPreferences() != null && user.getNotificationPreferences().isEmailEnabled())
                .notifyBeforeMinutes(user.getNotificationPreferences() != null ? user.getNotificationPreferences().getNotifyBeforeMinutes() : null)
                .fcmActive(user.getNotificationPreferences() != null && user.getNotificationPreferences().isFcmActive())

                .build();
    }



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
            dto.setFullName(user.getProfileInfo().getName() + " " + user.getProfileInfo().getSurname());
            dto.setEmail(user.getProfileInfo().getEmail());
        }

        return dto;
    }


}
