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

    // Konum bazlı arama
    private Double latitude;
    private Double longitude;
    private Double radiusKm = 5.0; // Varsayılan 5km

    // Metin bazlı arama
    private String name;
    private String city;
    private String district;

    // Ödeme yöntemi filtresi
    private List<PaymentMethod> paymentMethods;

    // Durum filtresi
    private Boolean active;

    // Çalışma saatleri
    private String workingHours;
}