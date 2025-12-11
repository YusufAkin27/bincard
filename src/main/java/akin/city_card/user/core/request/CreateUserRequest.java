package akin.city_card.user.core.request;

import akin.city_card.validations.UniqueEmail;
import akin.city_card.validations.UniquePhoneNumber;
import akin.city_card.validations.ValidEmail;
import akin.city_card.validations.ValidPassword;
import akin.city_card.validations.ValidTelephone;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CreateUserRequest {
    @NotNull(message = "isim boş olamaz")
    private String firstName;

    @NotNull(message = "soyisim boş olamaz")
    private String lastName;

    @ValidTelephone
    @UniquePhoneNumber
    private String telephone;
    @ValidPassword
    private String password;

    @ValidEmail
    @UniqueEmail
    private String email;

}


