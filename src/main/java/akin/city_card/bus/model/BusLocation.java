package akin.city_card.bus.model;

import akin.city_card.bus.model.Bus;
import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
public class BusLocation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Bus bus;

    private double latitude;
    private double longitude;

    private LocalDateTime timestamp;
}
