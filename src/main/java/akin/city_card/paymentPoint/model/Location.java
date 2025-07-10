package akin.city_card.paymentPoint.model;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Data;

@Embeddable
@Data
public class Location {

    @Column(nullable = false)
    private double latitude;

    @Column(nullable = false)
    private double longitude;
}
