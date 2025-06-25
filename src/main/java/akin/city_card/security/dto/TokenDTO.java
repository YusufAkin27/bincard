package akin.city_card.security.dto;

import akin.city_card.security.entity.enums.TokenType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenDTO {
    private String token;               // tokenValue
    private LocalDateTime issuedAt;
    private LocalDateTime expiresAt;
    private LocalDateTime lastUsedAt;
    private String ipAddress;
    private String deviceInfo;
    private TokenType tokenType;


}
