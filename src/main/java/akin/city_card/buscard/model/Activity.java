package akin.city_card.buscard.model;

import akin.city_card.bus.model.Bus;
import akin.city_card.route.model.Route;
import akin.city_card.station.model.Station;
import jakarta.persistence.*;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Data
public class Activity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDateTime useDateTime;
    private BigDecimal price;
    private boolean isTransfer;

    @ManyToOne
    private BusCard busCard;

    @ManyToOne
    private Bus bus;

    @ManyToOne
    private Station station;

    @ManyToOne
    private Route route;
}

