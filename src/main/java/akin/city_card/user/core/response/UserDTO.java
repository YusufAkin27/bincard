package akin.city_card.user.core.response;

import akin.city_card.notification.model.NotificationPreferences;
import akin.city_card.wallet.model.Wallet;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@Builder
public class UserDTO {
    private String name;
    private String surname;
    private String email;
    private String phoneNumber;

    private boolean phoneVerified;
    private boolean emailVerified;

    private String profilePicture;

    private String nationalId;
    private LocalDate birthDate;
    private boolean walletActivated;

    private boolean allowNegativeBalance;
    private Double negativeBalanceLimit;
    private boolean autoTopUpEnabled;

    private NotificationPreferences notificationPreferences;
}
