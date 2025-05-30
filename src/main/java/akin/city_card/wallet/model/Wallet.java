package akin.city_card.wallet.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Entity
public class Wallet {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private BigDecimal balance = BigDecimal.ZERO;

    @OneToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @OneToMany(mappedBy = "wallet", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<WalletTransaction> transactions;

    private LocalDateTime lastUpdated;

    // NFC ile para gönderme gibi işlemler için geçici doğrulama kodu
    private String activeTransferCode;

    private LocalDateTime transferCodeExpiresAt;
}
