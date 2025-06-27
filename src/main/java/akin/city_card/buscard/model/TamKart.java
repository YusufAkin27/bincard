package akin.city_card.buscard.model;

import jakarta.persistence.Entity;

import java.math.BigDecimal;

@Entity
public class TamKart extends BusCard {
    private BigDecimal fixedFare;

}
