package akin.city_card.user.core.response;

import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
public class UserExportDTO {

    private Long id;

    private String userNumber;

    private String nationalId;

    private LocalDate birthDate;

    private boolean walletActivated;

    private boolean allowNegativeBalance;

    private Double negativeBalanceLimit;

    private boolean autoTopUpEnabled;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    private String fullName;      // profileInfo içinden alınabilir

    private String email;         // profileInfo içinden alınabilir


}
