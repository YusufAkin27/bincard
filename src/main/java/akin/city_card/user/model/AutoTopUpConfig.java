package akin.city_card.user.model;

import akin.city_card.buscard.model.BusCard;
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

    // Hangi kullanıcıya ait
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Hangi otobüs kartı için geçerli
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "bus_card_id", nullable = false)
    private BusCard busCard;

    // Ödeme yöntemi token'ı (Stripe, iyzico vb. tarafından verilen)
    @Column(nullable = false, length = 100)
    private String paymentMethodId;

    // Ödeme sağlayıcı tipi (örneğin "STRIPE", "IYZICO" vs.)
    @Column(nullable = false, length = 20)
    private String paymentProvider;

    // Bakiye bu eşik altına inerse yükleme yapılır
    @Column(nullable = false)
    private double threshold;

    // Yüklenecek miktar
    @Column(nullable = false)
    private double amount;

    // Aktiflik durumu
    private boolean active = true;

    // Son başarılı otomatik yükleme tarihi (opsiyonel, takip için)
    private LocalDateTime lastTopUpAt;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "autoTopUpConfig", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AutoTopUpLog> autoTopUpLogs;
}
