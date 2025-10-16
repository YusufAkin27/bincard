package akin.city_card.paymentPoint.core.request;

import akin.city_card.paymentPoint.core.response.AddressDTO;
import akin.city_card.paymentPoint.core.response.LocationDTO;
import akin.city_card.paymentPoint.model.PaymentMethod;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AddPaymentPointRequest {

    @NotBlank(message = "Ödeme noktası ismi boş olamaz")
    @Size(max = 150, message = "Ödeme noktası ismi 150 karakterden fazla olamaz")
    private String name;

    @Valid
    @NotNull(message = "Konum bilgisi zorunludur")
    private LocationDTO location;

    @Valid
    @NotNull(message = "Adres bilgisi zorunludur")
    private AddressDTO address;

    @Size(max = 20, message = "İletişim numarası 20 karakterden fazla olamaz")
    private String contactNumber;

    @Size(max = 100, message = "Çalışma saatleri 100 karakterden fazla olamaz")
    private String workingHours;

    @NotEmpty(message = "En az bir ödeme yöntemi seçilmelidir")
    private List<PaymentMethod> paymentMethods;

    @Size(max = 1000, message = "Açıklama 1000 karakterden fazla olamaz")
    private String description;

    private boolean active = true;
}