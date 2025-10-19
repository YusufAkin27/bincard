package akin.city_card.wallet.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "wallet_status_logs")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WalletStatusLog extends AuditableEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "wallet_id", nullable = false)
    private Wallet wallet;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private WalletStatus oldStatus;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private WalletStatus newStatus;

    @Column(nullable = false)
    private LocalDateTime changedAt;

    @Column(length = 255)
    private String reason;

    @Column(nullable = false)
    private Long changedByUserId;
}
