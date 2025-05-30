package akin.city_card.station.model;

import akin.city_card.route.model.Route;
import jakarta.persistence.*;

import java.util.List;
@Entity
public class Station {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String address;
}
