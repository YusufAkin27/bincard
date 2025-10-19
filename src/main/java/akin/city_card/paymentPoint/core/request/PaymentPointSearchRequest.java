package akin.city_card.paymentPoint.core.request;

import akin.city_card.paymentPoint.model.PaymentMethod;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PaymentPointSearchRequest {

    private Double latitude;
    private Double longitude;
    private Double radiusKm = 5.0; // Varsayılan 5km

    private String name;
    private String city;
    private String district;

    private List<PaymentMethod> paymentMethods;

    private Boolean active;

    private String workingHours;
}