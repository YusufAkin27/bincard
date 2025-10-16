package akin.city_card.paymentPoint.model;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Embeddable
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Address {
    @Column(length = 255, columnDefinition = "VARCHAR(255)")
    private String street;

    @Column(length = 100, columnDefinition = "VARCHAR(100)")
    private String district;

    @Column(length = 100, columnDefinition = "VARCHAR(100)")
    private String city;

    @Column(length = 20, columnDefinition = "VARCHAR(20)")
    private String postalCode;
}
