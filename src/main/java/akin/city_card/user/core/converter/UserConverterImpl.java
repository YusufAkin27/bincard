package akin.city_card.user.core.converter;

import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.IdentityVerificationRequestDTO;
import akin.city_card.user.core.response.SearchHistoryDTO;
import akin.city_card.user.core.response.UserIdentityInfoDTO;
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
    public SearchHistoryDTO toDto(SearchHistory sh) {
        return SearchHistoryDTO.builder()
                .id(sh.getId())
                .userId(sh.getUser().getId())
                .query(sh.getQuery())
                .active(sh.isActive())
                .searchedAt(sh.getSearchedAt())
                .searchType(sh.getSearchType())
                .deleted(sh.isDeleted())
                .deletedAt(sh.getDeletedAt())
                .createdAt(sh.getCreatedAt())
                .build();
    }

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
        if (user == null) return null;
        return CacheUserDTO.builder()
                .id(user.getId())
                .telephone(user.getUserNumber())

                // Profile Info
                .name(user.getProfileInfo() != null ? user.getProfileInfo().getName() : null)
                .surname(user.getProfileInfo() != null ? user.getProfileInfo().getSurname() : null)
                .email(user.getProfileInfo() != null ? user.getProfileInfo().getEmail() : null)
                .profilePicture(user.getProfileInfo() != null ? user.getProfileInfo().getProfilePicture() : null)
                .status(user.getStatus())
                .deleted(user.isDeleted())
                // Device Info
                .fcmToken(user.getCurrentDeviceInfo() != null ? user.getCurrentDeviceInfo().getFcmToken() : null)

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
    public User convertUserToCreateUser(CreateUserRequest request) {
        ProfileInfo profileInfo = ProfileInfo.builder()
                .name(request.getFirstName())
                .surname(request.getLastName())
                .profilePicture("https://upload.wikimedia.org/wikipedia/commons/a/ac/Default_pfp.jpg")
                .build();
        DeviceInfo deviceInfo = DeviceInfo.builder()
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
                .currentDeviceInfo(deviceInfo)
                .build();
    }


}
