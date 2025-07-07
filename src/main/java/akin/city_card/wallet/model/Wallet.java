package akin.city_card.wallet.model;

import akin.city_card.user.model.User;
import io.craftgate.model.Currency;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static io.craftgate.model.Currency.TRY;

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

    @Column(name = "wiban", unique = true, nullable = false, length = 30)
    private String wiban;

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


    @PrePersist
    private void generateWibanIfAbsent() {
        if (this.wiban == null || this.wiban.isEmpty()) {
            try {
                String base = "CW" // CityWallet prefix
                        + "-" + user.getId()
                        + "-" + user.getIdentityInfo().getNationalId().substring(0, 3)
                        + "-" + user.getIdentityInfo().getBirthDate().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd"))
                        + "-" + System.currentTimeMillis();

                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(base.getBytes());

                // Hash'teki her byte'ı pozitif int yapıp stringe çevir ve sadece rakamlar elde et
                StringBuilder digitsOnly = new StringBuilder();
                for (byte b : hash) {
                    int val = b & 0xFF; // byte'ı unsigned int yap
                    digitsOnly.append(String.format("%03d", val)); // 3 basamaklı sayıya çevir, örn 005, 123 gibi
                }

                // İlk 16 haneyi al (başına "WBN-" eklenince toplam 20 karakter olur)
                String numericPart = digitsOnly.substring(0, 16);

                this.wiban = "WBN-" + numericPart;

            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("WIBAN üretiminde hata", e);
            }
        }
    }


}
