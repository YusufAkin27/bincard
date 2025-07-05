package akin.city_card.user.model;

import akin.city_card.buscard.model.BusCard;
import akin.city_card.wallet.model.Wallet;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AutoTopUpConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "bus_card_id", nullable = false)
    private BusCard busCard;

    // 💸 CÜZDAN üzerinden ödeme desteği
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "wallet_id")
    private Wallet wallet;

    @Column(nullable = false)
    private double threshold;

    @Column(nullable = false)
    private double amount;

    private boolean active = true;

    private LocalDateTime lastTopUpAt;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "config", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AutoTopUpLog> autoTopUpLogs;
}
