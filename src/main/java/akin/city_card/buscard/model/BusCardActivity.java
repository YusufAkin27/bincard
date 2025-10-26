package akin.city_card.buscard.model;

import akin.city_card.bus.model.Bus;
import akin.city_card.route.model.Route;
import akin.city_card.station.model.Station;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;


@Entity
@Data
public class BusCardActivity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDateTime useDateTime;

    private BigDecimal price;

    private boolean isTransfer;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "bus_card_id")
    private BusCard busCard;

    private String validatorId;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "bus_id")
    private Bus bus;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "station_id")
    private Station station;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "route_id")
    private Route route;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
}
