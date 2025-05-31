package akin.city_card.bus.model;

import akin.city_card.route.model.Route;
import jakarta.persistence.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Entity
public class Bus {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String numberPlate;

    @ManyToOne
    private Route route;

    private boolean active;

    // Eklenmesi önerilen:
    private double currentLatitude;
    private double currentLongitude;
    private LocalDateTime lastLocationUpdate;
}

