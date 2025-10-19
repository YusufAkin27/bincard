package akin.city_card.user.core.response;

import akin.city_card.user.model.UserStatus;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDate;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CacheUserDTO implements Serializable {

    @JsonView(Views.Admin.class)
    private Long id;

    @JsonView(Views.Public.class)
    private String telephone;

    @JsonView(Views.Admin.class)
    private boolean deleted;

    // ProfileInfo
    @JsonView(Views.Public.class)
    private String name;

    @JsonView(Views.Public.class)
    private String surname;

    @JsonView(Views.User.class)
    private String email;

    @JsonView(Views.Public.class)
    private String profilePicture;

    @JsonView(Views.Admin.class)
    private UserStatus status;

    // DeviceInfo
    @JsonView(Views.Admin.class)
    private String fcmToken;

    @JsonView(Views.Admin.class)
    private String deviceUuid;

    @JsonView(Views.User.class)
    private boolean phoneVerified;

    @JsonView(Views.User.class)
    private boolean emailVerified;

    @JsonView(Views.User.class)
    private LocalDate birthDate;

    @JsonView(Views.Admin.class)
    private String nationalId;

    @JsonView(Views.User.class)
    private boolean walletActivated;

    @JsonView(Views.Admin.class)
    private boolean allowNegativeBalance;

    @JsonView(Views.Admin.class)
    private Double negativeBalanceLimit;

    @JsonView(Views.User.class)
    private boolean autoTopUpEnabled;

    @JsonView(Views.Admin.class)
    private Set<String> roles;

    // NotificationPreferences
    @JsonView(Views.User.class)
    private boolean pushEnabled;

    @JsonView(Views.User.class)
    private boolean smsEnabled;

    @JsonView(Views.User.class)
    private boolean emailEnabled;

    @JsonView(Views.User.class)
    private Integer notifyBeforeMinutes;

    @JsonView(Views.Admin.class)
    private boolean fcmActive;
}
