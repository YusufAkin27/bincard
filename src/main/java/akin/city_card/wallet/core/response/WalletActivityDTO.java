package akin.city_card.wallet.core.response;

import akin.city_card.user.core.response.Views;
import akin.city_card.wallet.model.WalletActivityType;
import akin.city_card.wallet.model.WalletStatus;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class WalletActivityDTO {

    @JsonView(Views.Public.class)
    private Long id;

    @JsonView(Views.Public.class)
    private WalletActivityType activityType;

    @JsonView(Views.Public.class)
    private Long transactionId;

    @JsonView(Views.Public.class)
    private Long transferId;

    @JsonView(Views.Public.class)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime activityDate;

    @JsonView(Views.Public.class)
    private String description;

    @JsonView(Views.Admin.class)
    private Long walletId;

    @JsonView(Views.Admin.class)
    private String transactionType; // Örn: "TRANSFER", "TOP_UP", "WITHDRAWAL"

    @JsonView(Views.Admin.class)
    private String transactionStatus;

    @JsonView(Views.Admin.class)
    private BigDecimal amount;

    @JsonView(Views.Admin.class)
    private String performedBy; // İşlemi yapan kullanıcı adı veya kullanıcı ID'si

    @JsonView(Views.Admin.class)
    private String walletOwnerName; // Cüzdan sahibinin adı (opsiyonel)

    @JsonView(Views.Admin.class)
    private String currency; // Para birimi

    @JsonView(Views.Admin.class)
    private WalletStatus walletStatus; // Cüzdan durumu (aktif, pasif vb.)

    // Örnek ek alan: işlem ya da transferin detay linki / ID bilgisi
    @JsonView(Views.Admin.class)
    private String referenceCode;

}
