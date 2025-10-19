package akin.city_card.bus.model;

import akin.city_card.buscard.model.CardType;
import akin.city_card.driver.model.Driver;
import akin.city_card.route.model.Route;
import akin.city_card.route.model.RouteDirection;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.station.model.Station;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;


@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "buses")
public class Bus {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String validatorId;



    @Column(nullable = false, unique = true, length = 20)
    private String numberPlate;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assigned_route_id")
    private Route assignedRoute;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "current_direction_id")
    private RouteDirection currentDirection;


    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "driver_id")
    private Driver driver;


    @Column(nullable = false)
    private boolean isActive = true;

    @Column(nullable = false)
    private double baseFare;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private BusStatus status = BusStatus.CALISIYOR;


    @Column(nullable = false)
    private int capacity = 50; // Varsayılan kapasite


    @Column(nullable = false)
    private int currentPassengerCount = 0;

    private Double currentLatitude;
    private Double currentLongitude;
    private LocalDateTime lastLocationUpdate;
    private Double lastKnownSpeed;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "last_seen_station_id")
    private Station lastSeenStation;

    private LocalDateTime lastSeenStationTime;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "next_station_id")
    private Station nextStation;


    private Integer estimatedArrivalMinutes;

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

    @OneToMany(mappedBy = "bus", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<BusRide> rides;

    @OneToMany(mappedBy = "bus", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<BusLocation> locationHistory;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }


    public boolean isFull() {
        return currentPassengerCount >= capacity;
    }

    public double getOccupancyRate() {
        return capacity > 0 ? (double) currentPassengerCount / capacity * 100 : 0;
    }


    public void switchDirection() {
        if (assignedRoute != null && currentDirection != null) {
            if (currentDirection.equals(assignedRoute.getOutgoingDirection())) {
                currentDirection = assignedRoute.getReturnDirection();
            } else {
                currentDirection = assignedRoute.getOutgoingDirection();
            }
        }
    }


    public String getRouteDisplayName() {
        return assignedRoute != null ? assignedRoute.getName() : "Atanmamış";
    }


    public String getRouteCode() {
        return assignedRoute != null ? assignedRoute.getCode() : null;
    }


    public String getDriverDisplayName() {
        if (driver != null && driver.getProfileInfo() != null) {
            return driver.getProfileInfo().getName() + " " + driver.getProfileInfo().getSurname();
        }
        return "Atanmamış";
    }


    public String getCurrentDirectionName() {
        return currentDirection != null ? currentDirection.getName() : "Belirsiz";
    }
}