package akin.city_card.route.model;

import akin.city_card.security.entity.SecurityUser;
import akin.city_card.station.model.Station;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Ana rota sınıfı - Her rota iki yönlü olacak (gidiş-dönüş)
 * Örnek: "Kadıköy - Taksim" rotası
 */
@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "routes")
public class Route {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Rota adı - Örnek: "Kadıköy - Taksim", "Üniversite - Merkez"
     */
    @Column(nullable = false, length = 100)
    private String name;

    /**
     * Rota kodu - Örnek: "34A", "M1", "142"
     */
    @Column(nullable = false, unique = true, length = 10)
    private String code;

    /**
     * Rota açıklaması
     */
    @Column(length = 500)
    private String description;

    /**
     * Rotanın başlangıç durağı
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "start_station_id", nullable = false)
    private Station startStation;

    /**
     * Rotanın bitiş durağı
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "end_station_id", nullable = false)
    private Station endStation;

    /**
     * Rotanın aktif olup olmadığı
     */
    @Column(nullable = false)
    private boolean isActive = true;

    /**
     * Rota rengi (harita gösterimi için)
     */
    @Column(length = 7)
    private String color; // Hex color code

    /**
     * Tahmini süre (dakika)
     */
    private Integer estimatedDurationMinutes;

    /**
     * Toplam mesafe (kilometre)
     */
    private Double totalDistanceKm;

    /**
     * Rota tipi
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RouteType routeType = RouteType.CITY_BUS;

    /**
     * Çalışma saatleri bilgisi
     */
    @Embedded
    private RouteSchedule schedule;

    /**
     * Bu rotanın iki yönü (gidiş ve dönüş)
     */
    @OneToMany(mappedBy = "route", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<RouteDirection> directions;

    // Audit fields
    @Column(nullable = false)
    private boolean isDeleted = false;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
    private LocalDateTime deletedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private SecurityUser createdBy;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "updated_by")
    private SecurityUser updatedBy;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "deleted_by")
    private SecurityUser deletedBy;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Gidiş yönünü getir
     */
    public RouteDirection getOutgoingDirection() {
        return directions.stream()
                .filter(direction -> direction.getType() == DirectionType.GIDIS)
                .findFirst()
                .orElse(null);
    }

    /**
     * Dönüş yönünü getir
     */
    public RouteDirection getReturnDirection() {
        return directions.stream()
                .filter(direction -> direction.getType() == DirectionType.DONUS)
                .findFirst()
                .orElse(null);
    }
}