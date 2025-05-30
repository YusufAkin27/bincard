package akin.city_card.route.model;

import akin.city_card.station.model.Station;
import jakarta.persistence.*;

import java.util.List;
@Entity
public class Route {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    @ManyToMany
    private List<Station> stations;
}

