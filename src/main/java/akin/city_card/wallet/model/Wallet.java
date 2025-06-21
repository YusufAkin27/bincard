package akin.city_card.wallet.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;



import lombok.*;
import org.hibernate.annotations.UpdateTimestamp;


import java.util.ArrayList;

@Entity
@Table(name = "wallets")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Wallet extends AuditableEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private Currency currency = Currency.TRY;


    @Column(nullable = false, precision = 19, scale = 4)
    private BigDecimal balance = BigDecimal.ZERO;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", unique = true, nullable = false)
    private User user;

    @OneToMany(mappedBy = "wallet", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<WalletTransaction> transactions = new ArrayList<>();

    @UpdateTimestamp
    private LocalDateTime lastUpdated;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private WalletStatus status = WalletStatus.ACTIVE;

    @Column(length = 20)
    private String activeTransferCode;

    private LocalDateTime transferCodeExpiresAt;

    @Column(nullable = false)
    private int totalTransactionCount = 0;

    @OneToMany(mappedBy = "wallet", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<WalletStatusLog> statusLogs = new ArrayList<>();
}
