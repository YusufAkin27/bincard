package akin.city_card.paymentPoint.core.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PaymentPhotoDTO {

    private Long id;
    private String imageUrl;
}