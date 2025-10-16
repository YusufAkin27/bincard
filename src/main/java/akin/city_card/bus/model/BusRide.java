package akin.city_card.bus.model;

import akin.city_card.buscard.model.BusCard;
import jakarta.persistence.*;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Data
public class BusRide {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Biniş yapılan otobüs
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private Bus bus;

    // Yolcuya ait kart
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private BusCard busCard;

    // Biniş zamanı
    @Column(nullable = false)
    private LocalDateTime boardingTime;

    // Hesaplanan ücret
    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal fareCharged;

    // İşlem durumu
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RideStatus status;

    // Otomatik tarih takibi eklenebilir
    @PrePersist
    public void prePersist() {
        if (boardingTime == null) {
            boardingTime = LocalDateTime.now();
        }
    }
}
