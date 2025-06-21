package akin.city_card.paymentPoint.model;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

@Embeddable
public class Address {

    @Column(length = 255)
    private String street;

    @Column(length = 100)
    private String district;

    @Column(length = 100)
    private String city;

    @Column(length = 20)
    private String postalCode;
}
