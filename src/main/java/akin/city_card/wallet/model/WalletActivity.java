package akin.city_card.wallet.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "wallet_activities")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WalletActivity extends AuditableEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Version
    private Long version;

    @Column(nullable = false)
    private Long walletId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private WalletActivityType activityType;

    private Long transactionId;

    private Long transferId;

    @Column(nullable = false)
    private LocalDateTime activityDate;

    @Column(length = 255)
    private String description;
}
