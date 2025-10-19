package akin.city_card.route.model;

import akin.city_card.station.model.Station;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Rota yönündeki duraklar arası bağlantı
 * A durağından B durağına geçişi temsil eder
 */
@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(
        name = "route_station_nodes",
        indexes = {
                @Index(name = "idx_direction_sequence", columnList = "direction_id, sequenceOrder"),
                @Index(name = "idx_from_to_station", columnList = "from_station_id, to_station_id")
        }
)
public class RouteStationNode {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "direction_id", nullable = false)
    private RouteDirection direction;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "from_station_id", nullable = false)
    private Station fromStation;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "to_station_id", nullable = false)
    private Station toStation;

    @Column(nullable = false)
    private int sequenceOrder;

    private Integer estimatedTravelTimeMinutes;

    private Double distanceKm;

    @Column(nullable = false)
    private boolean isActive = true;


    @Column(length = 500)
    private String notes;


}