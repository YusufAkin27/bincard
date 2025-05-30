package akin.city_card.wallet.model;

import akin.city_card.wallet.model.TransactionType;
import akin.city_card.wallet.model.Wallet;
import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
public class WalletTransaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Wallet wallet;

    private BigDecimal amount;

    @Enumerated(EnumType.STRING)
    private TransactionType type; // LOAD, RIDE, TRANSFER_OUT, TRANSFER_IN, REFUND

    private LocalDateTime timestamp;

    private String description;

    private String externalReference; // banka işlemi, QR kod ID’si vs.
}

