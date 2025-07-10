package akin.city_card.paymentPoint.core.response;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AddressDTO {

    @Size(max = 255, message = "Sokak bilgisi 255 karakterden fazla olamaz")
    private String street;

    @Size(max = 100, message = "İlçe bilgisi 100 karakterden fazla olamaz")
    private String district;

    @NotBlank(message = "Şehir bilgisi zorunludur")
    @Size(max = 100, message = "Şehir bilgisi 100 karakterden fazla olamaz")
    private String city;

    @Size(max = 20, message = "Posta kodu 20 karakterden fazla olamaz")
    private String postalCode;
}