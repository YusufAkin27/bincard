package akin.city_card.activity.model;

import akin.city_card.bus.model.Bus;
import akin.city_card.card.model.Card;
import akin.city_card.station.model.Station;
import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
public class Activity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDateTime useDateTime;
    private BigDecimal price;
    private boolean isTransfer; // önceki binişten kısa süre sonra mı?

    @ManyToOne
    private Card card;

    @ManyToOne
    private Bus bus;

    @ManyToOne
    private Station station;
}
