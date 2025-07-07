package akin.city_card.user.model;

import akin.city_card.route.model.Route;
import akin.city_card.station.model.Station;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "geo_alert")
public class GeoAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Hangi kullanıcıya ait
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Uyarı hangi rotaya ait
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "route_id", nullable = false)
    private Route route;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "station_id", nullable = false)
    private Station station;

    @Builder.Default
    @Column(nullable = false)
    private double radiusMeters = 300; // Varsayılan 300m

    @Builder.Default
    @Column(nullable = false)
    private int notifyBeforeMinutes = 5;

    @Builder.Default
    @Column(nullable = false)
    private boolean active = true;

    @Column(length = 100, nullable = false)
    private String alertName; // Kullanıcı dostu isim

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;
}
