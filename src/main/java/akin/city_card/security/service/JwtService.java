package akin.city_card.security.service;


import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.entity.Token;
import akin.city_card.security.entity.enums.TokenType;
import akin.city_card.security.exception.TokenIsExpiredException;
import akin.city_card.security.exception.TokenNotFoundException;
import akin.city_card.security.repository.TokenRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;
@Service
public class JwtService {

    private final String accessSecret = "fdkjlsjfkldsjfkldafhliehdjkshgajkjkfincvxkjuvzimfjnvxivoinerji432jkisdfvcxio4";
    private final String refreshSecret = "fajsdfkljslnzufhugeqyewqwiopeoiqueyuyzIOyz786e786wrtwfgyiyzyuiyzuiunewrwrsxg";

    @Autowired
    private TokenRepository tokenRepository;

    public String generateAccessToken(SecurityUser user, String ipAddress, String deviceInfo, LocalDateTime expiresAt) {
        LocalDateTime issuedAt = LocalDateTime.now(); // tek bir kaynak
        String accessToken = generateToken(user, accessSecret, issuedAt, expiresAt, true);
        saveToken(user, accessToken, issuedAt, expiresAt, TokenType.ACCESS, ipAddress, deviceInfo);
        return accessToken;
    }

    public String generateRefreshToken(SecurityUser user, String ipAddress, String deviceInfo, LocalDateTime expiresAt) {
        LocalDateTime issuedAt = LocalDateTime.now();
        String refreshToken = generateToken(user, refreshSecret, issuedAt, expiresAt, false);
        saveToken(user, refreshToken, issuedAt, expiresAt, TokenType.REFRESH, ipAddress, deviceInfo);
        return refreshToken;
    }


    private String generateToken(SecurityUser user, String secret, LocalDateTime issuedAt, LocalDateTime expiresAt, boolean includeClaims) {
        Date issued = Date.from(issuedAt.atZone(ZoneId.systemDefault()).toInstant());
        Date expiration = Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant());

        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(issued)
                .setExpiration(expiration)
                .signWith(getSignSecretKey(secret));

        if (includeClaims) {
            jwtBuilder.claim("userNumber", user.getUserNumber())
                    .claim("role", user.getRoles());
        }

        return jwtBuilder.compact();
    }


    private SecretKey getSignSecretKey(String secret) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private void saveToken(SecurityUser user, String tokenValue, LocalDateTime issuedAt, LocalDateTime expiresAt, TokenType tokenType, String ipAddress, String deviceInfo) {
        tokenRepository.findTokenBySecurityUser_IdAndTokenType(user.getId(), tokenType)
                .ifPresent(tokenRepository::delete);

        Token token = new Token();
        token.setTokenValue(tokenValue);
        token.setSecurityUser(user);
        token.setTokenType(tokenType);
        token.setIssuedAt(issuedAt);
        token.setExpiresAt(expiresAt);
        token.setIpAddress(ipAddress);
        token.setDeviceInfo(deviceInfo);
        token.setValid(true);

        tokenRepository.save(token);
    }



    private boolean validateToken(String token, String secret) throws TokenIsExpiredException, TokenNotFoundException {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getSignSecretKey(secret))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            Optional<Token> tokenEntity = tokenRepository.findByTokenValue(token);

            if (tokenEntity.isEmpty() || !tokenEntity.get().isValid()) {
                throw new TokenNotFoundException();
            }

            if (tokenEntity.get().getExpiresAt().isBefore(LocalDateTime.now())) {
                throw new TokenIsExpiredException();
            }

            return true;
        } catch (ExpiredJwtException e) {
            throw new TokenIsExpiredException();
        } catch (JwtException e) {
            throw new TokenNotFoundException();
        }
    }

    public boolean validateRefreshToken(String token) throws TokenIsExpiredException, TokenNotFoundException {
        return validateToken(token, refreshSecret);
    }

    public boolean validateAccessToken(String token) throws TokenIsExpiredException, TokenNotFoundException {
        return validateToken(token, accessSecret);
    }

    public Claims getAccessTokenClaims(String token) {
        return getClaims(token, accessSecret);
    }

    public Claims getRefreshTokenClaims(String token) {
        return getClaims(token, refreshSecret);
    }

    public String extractUsernameFromToken(String token) {
        Claims claims = getClaims(token, accessSecret);
        return claims.getSubject();
    }

    public Claims getClaims(@NonNull String token, @NonNull String secretKey) {
        return Jwts.parser()
                .setSigningKey(getSignSecretKey(secretKey))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    public String extractUsername(String token) {
        Optional<Token> optionalToken = tokenRepository.findByTokenValue(token);
        Token token1;
        if (optionalToken.isEmpty()) {
            return null;
        }
        token1 = optionalToken.get();
        return token1.getSecurityUser().getUsername();
    }


}
