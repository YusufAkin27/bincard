package akin.city_card.wallet.core.response;

import akin.city_card.user.core.response.Views;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class TransferDetailsDTO {

    @JsonView(Views.Public.class)
    private Long id;

    @JsonView(Views.Public.class)
    private BigDecimal amount;

    @JsonView(Views.Public.class)
    private String status;

    @JsonView(Views.Public.class)
    private LocalDateTime initiatedAt;

    @JsonView(Views.Admin.class)
    private LocalDateTime completedAt;

    @JsonView(Views.SuperAdmin.class)
    private String description;

    @JsonView(Views.SuperAdmin.class)
    private Long initiatedByUserId;

    @JsonView(Views.SuperAdmin.class)
    private String cancellationReason;

    @JsonView(Views.SuperAdmin.class)
    private Long senderWalletId;

    @JsonView(Views.SuperAdmin.class)
    private Long receiverWalletId;

    @JsonView(Views.SuperAdmin.class)
    private String senderUserName; // Kullanıcı adı, varsa

    @JsonView(Views.SuperAdmin.class)
    private String receiverUserName; // Kullanıcı adı, varsa
}
