package akin.city_card.bus.model;

import akin.city_card.buscard.model.CardType;
import akin.city_card.driver.model.Driver;
import akin.city_card.route.model.Route;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Bus {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String numberPlate;  // Otobüs plakası, benzersiz

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    private Route route; // Otobüsün rotası

    @OneToOne(optional = false, fetch = FetchType.LAZY)
    private Driver driver; // Otobüsün şoförü

    @Column(nullable = false)
    private boolean active = true; // Otobüsün aktifliği

    @Column(nullable = false)
    private double fare; // Tam bilet fiyatı

    // --- Anlık konum bilgileri ---
    private double currentLatitude;  // Son bilinen enlem
    private double currentLongitude; // Son bilinen boylam
    private LocalDateTime lastLocationUpdate; // Son konum güncelleme zamanı

    private LocalDateTime createdAt;  // Kayıt oluşturulma zamanı
    private LocalDateTime updatedAt;  // Kayıt son güncellenme zamanı

    @OneToMany(mappedBy = "bus", cascade = CascadeType.ALL)
    private List<BusRide> rides;  // Bu otobüse ait biniş kayıtları

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Kart tipine göre ücret hesaplama fonksiyonu.
     */
    public double calculateFare(CardType cardType) {
        switch (cardType) {
            case ÖĞRENCİ: return fare * 0.5;
            case ÖĞRETMEN: return fare * 0.75;
            case YAŞLI: return fare * 0.6;
            case ENGELLİ: return fare * 0.4;
            case ÇOCUK: return fare * 0.3;
            case TURİST: return fare * 1.2;
            case ABONMAN: return 0.0;
            case TAM:
            default: return fare;
        }
    }
}

