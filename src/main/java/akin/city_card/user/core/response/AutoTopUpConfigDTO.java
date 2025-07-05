package akin.city_card.user.core.response;

import akin.city_card.buscard.model.BusCard;
import akin.city_card.user.model.AutoTopUpLog;
import akin.city_card.user.model.User;
import akin.city_card.wallet.model.Wallet;
import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;


import java.time.LocalDateTime;
import java.util.List;

@Data
public class AutoTopUpConfigDTO {

    private Long id;

    private Long userId;
    private Long busCardId;

    private Long walletId;

    private double threshold;

    private double amount;

    private boolean active ;

    private LocalDateTime lastTopUpAt;

    private LocalDateTime createdAt;
}

