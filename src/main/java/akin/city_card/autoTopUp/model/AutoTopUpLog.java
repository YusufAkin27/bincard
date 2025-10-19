package akin.city_card.autoTopUp.model;

import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AutoTopUpLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Hangi otomatik yükleme konfigürasyonu üzerinden gerçekleşti
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "config_id", nullable = false)
    private AutoTopUpConfig config;

    private LocalDateTime timestamp;

    private BigDecimal amount;

    private boolean success;

    private String failureReason; // Boşsa başarılıdır
}
