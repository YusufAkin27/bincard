package akin.city_card.paymentPoint.core.response;

import akin.city_card.paymentPoint.model.PaymentMethod;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PaymentPointDTO {

    private Long id;
    private String name;
    private LocationDTO location;
    private AddressDTO address;
    private String contactNumber;
    private String workingHours;
    private List<PaymentMethod> paymentMethods;
    private String description;
    private boolean active;
    private List<PaymentPhotoDTO> photos;
    private LocalDateTime createdAt;
    private LocalDateTime lastUpdated;

    // Konum bazlı arama için mesafe bilgisi (km)
    private Double distance;
}