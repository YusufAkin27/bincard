package akin.city_card.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenResponseDTO {
    private TokenDTO accessToken;
    private TokenDTO refreshToken;


}
