package akin.city_card.security.dto;

import akin.city_card.validations.ValidPassword;
import akin.city_card.validations.ValidTelephone;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LoginRequestDTO {

    // 🔐 Kimlik bilgileri
    @ValidTelephone
    private String telephone;   // Kullanıcı numarası (örn: telefon)
    @ValidPassword
    private String password;    // Şifre

}
