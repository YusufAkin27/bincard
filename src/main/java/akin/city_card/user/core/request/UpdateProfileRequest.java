package akin.city_card.user.core.request;

import akin.city_card.validations.UniqueEmail;
import akin.city_card.validations.ValidEmail;
import lombok.Data;

@Data
public class UpdateProfileRequest {
    private String name;           // ad
    private String surname;        // soyad
    @UniqueEmail
    @ValidEmail
    private String email;


}
