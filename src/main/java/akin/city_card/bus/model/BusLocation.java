package akin.city_card.bus.model;

import akin.city_card.bus.model.Bus;
import akin.city_card.driver.model.Driver;
import akin.city_card.route.model.Route;
import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
@Table(indexes = {
        @Index(name = "idx_bus_timestamp", columnList = "bus_id, timestamp")
})
public class BusLocation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    private Bus bus;

    @Column(nullable = false)
    private double latitude;

    @Column(nullable = false)
    private double longitude;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @PrePersist
    protected void onCreate() {
        timestamp = LocalDateTime.now();
    }
}
