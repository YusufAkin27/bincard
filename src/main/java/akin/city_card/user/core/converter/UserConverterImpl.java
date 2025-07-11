package akin.city_card.user.core.converter;

import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.*;
import akin.city_card.user.model.*;
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
    public UserIdentityInfoDTO toUserIdentityInfoDTO(UserIdentityInfo entity) {
        if (entity == null) return null;

        String approvedByPhone = null;
        if (entity.getApprovedBy() != null) {
            approvedByPhone = entity.getApprovedBy().getUserNumber();
        }

        String userPhone = null;
        if (entity.getUser() != null) {
            userPhone = entity.getUser().getUserNumber();
        }

        return UserIdentityInfoDTO.builder()
                .id(entity.getId())
                .frontCardPhoto(entity.getFrontCardPhoto())
                .backCardPhoto(entity.getBackCardPhoto())
                .nationalId(entity.getNationalId())
                .serialNumber(entity.getSerialNumber())
                .birthDate(entity.getBirthDate())
                .gender(entity.getGender())
                .motherName(entity.getMotherName())
                .fatherName(entity.getFatherName())
                .approved(entity.getApproved())
                .approvedAt(entity.getApprovedAt())
                .approvedByPhone(approvedByPhone)
                .userPhone(userPhone)
                .build();
    }
    @Override
    public IdentityVerificationRequestDTO convertToVerificationRequestDTO(IdentityVerificationRequest entity) {
        if (entity == null) return null;

        return IdentityVerificationRequestDTO.builder()
                .id(entity.getId())
                .identityInfo(toUserIdentityInfoDTO(entity.getIdentityInfo()))
                .requestedByPhone(
                        entity.getRequestedBy() != null
                                ? entity.getRequestedBy().getUserNumber()
                                : null
                )
                .requestedAt(entity.getRequestedAt())
                .status(entity.getStatus())
                .build();
    }



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
                .status(user.getStatus())
                .deleted(user.isDeleted())
                .password(user.getPassword())
                // Device Info
                .fcmToken(user.getDeviceInfo() != null ? user.getDeviceInfo().getFcmToken() : null)
                .deviceUuid(user.getDeviceInfo() != null ? user.getDeviceInfo().getDeviceUuid() : null)
                .phoneNumber(user.getDeviceInfo() != null ? user.getDeviceInfo().getIpAddress() : null) // eğer farklı alan kullanıyorsan değiştir

                .phoneVerified(user.isPhoneVerified())
                .emailVerified(user.isEmailVerified())
                .birthDate(user.getIdentityInfo() != null ? user.getIdentityInfo().getBirthDate() : null)
                .nationalId(user.getIdentityInfo() != null ? user.getIdentityInfo().getNationalId() : null)

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
    public SearchHistoryDTO toSearchHistoryDTO(SearchHistory searchHistory) {
        return SearchHistoryDTO.builder()
                .userId(searchHistory.getUser().getId())
                .query(searchHistory.getQuery())
                .active(searchHistory.isActive())
                .createdAt(searchHistory.getCreatedAt())
                .deletedAt(searchHistory.getDeletedAt())
                .deleted(searchHistory.isDeleted())
                .searchType(searchHistory.getSearchType())
                .searchedAt(searchHistory.getSearchedAt())
                .id(searchHistory.getId())
                .build();
    }

    @Override
    public GeoAlertDTO toGeoAlertDTO(GeoAlert geoAlert) {
        return GeoAlertDTO.builder()
                .id(geoAlert.getId())
                .alertName(geoAlert.getAlertName())
                .stationId(geoAlert.getStation().getId())
                .radiusMeters(geoAlert.getRadiusMeters())
                .routeId(geoAlert.getRoute().getId())
                .updatedAt(geoAlert.getUpdatedAt())
                .userId(geoAlert.getUser().getId())
                .createdAt(geoAlert.getCreatedAt())
                .notifyBeforeMinutes(geoAlert.getNotifyBeforeMinutes())
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
                .status(UserStatus.UNVERIFIED)
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


}
