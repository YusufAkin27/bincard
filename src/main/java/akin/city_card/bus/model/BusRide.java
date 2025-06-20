package akin.city_card.bus.model;

import akin.city_card.buscard.model.BusCard;
import akin.city_card.driver.model.Driver;
import akin.city_card.route.model.Route;
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

    // Hangi otobüse bindi
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private Bus bus;

    // Hangi rota üzerindeydi
    @ManyToOne(fetch = FetchType.LAZY)
    private Route route;

    // Binmeyi yapan kart (kullanıcı)
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private BusCard busCard;

    // O anki şoför (otobüsün şoförü zaten)
    @ManyToOne(fetch = FetchType.LAZY)
    private Driver driver;

    // Biniş zamanı
    @Column(nullable = false)
    private LocalDateTime boardingTime;

    // Ücret
    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal fareCharged;

    // İşlem durumu (başarılı, iptal vb.)
    @Enumerated(EnumType.STRING)
    private RideStatus status;
}