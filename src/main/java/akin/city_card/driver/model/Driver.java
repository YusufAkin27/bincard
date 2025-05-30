package akin.city_card.driver.model;

import akin.city_card.bus.model.Bus;
import ch.qos.logback.core.joran.event.BodyEvent;
import jakarta.persistence.*;

@Entity
public class Driver {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String surname;
    private String identityNumber;

    @OneToOne
    private Bus assignedBus;

    @Enumerated(EnumType.STRING)
    private Shift shift;
}


