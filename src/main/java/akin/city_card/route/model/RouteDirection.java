package akin.city_card.route.model;

import akin.city_card.station.model.Station;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Rotanın yönü (gidiş veya dönüş)
 * Her rota 2 RouteDirection'a sahip olur
 */
@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "route_directions")
public class RouteDirection {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 200)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private DirectionType type;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "route_id", nullable = false)
    private Route route;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "start_station_id", nullable = false)
    private Station startStation;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "end_station_id", nullable = false)
    private Station endStation;


    @OneToMany(mappedBy = "direction", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("sequenceOrder ASC")
    private List<RouteStationNode> stationNodes;

    private Integer estimatedDurationMinutes;

    private Double totalDistanceKm;

    @Column(nullable = false)
    private boolean isActive = true;


    public Station getStationByOrder(int order) {
        return stationNodes.stream()
                .filter(node -> node.getSequenceOrder() == order)
                .map(RouteStationNode::getToStation)
                .findFirst()
                .orElse(null);
    }

    public int getTotalStationCount() {
        return stationNodes != null ? stationNodes.size() + 1 : 1; // +1 for start station
    }
}