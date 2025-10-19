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
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    // Güvenli secret key'ler - Production'da environment variable'dan alınmalı
    @Value("${jwt.access.secret:#{null}}")
    private String accessSecretFromEnv;

    @Value("${jwt.refresh.secret:#{null}}")
    private String refreshSecretFromEnv;

    // Fallback secrets (development için)
    private final String fallbackAccessSecret = generateSecureSecret();
    private final String fallbackRefreshSecret = generateSecureSecret();

    private final TokenRepository tokenRepository;

    private String getAccessSecret() {
        return accessSecretFromEnv != null ? accessSecretFromEnv : fallbackAccessSecret;
    }

    private String getRefreshSecret() {
        return refreshSecretFromEnv != null ? refreshSecretFromEnv : fallbackRefreshSecret;
    }

    public String generateAccessToken(SecurityUser user, String ipAddress, String deviceInfo, LocalDateTime expiresAt) {
        LocalDateTime issuedAt = LocalDateTime.now();
        String jti = UUID.randomUUID().toString(); // Unique token identifier

        try {
            tokenRepository.deleteBySecurityUserAndTokenType(user, TokenType.ACCESS);
            tokenRepository.flush();
            logger.debug("Deleted existing ACCESS tokens for user: {}", user.getUsername());
        } catch (Exception e) {
            logger.warn("Failed to delete existing ACCESS tokens for user: {}", user.getUsername(), e);
        }

        String accessToken = generateToken(user, getAccessSecret(), issuedAt, expiresAt, true, jti);
        saveToken(user, accessToken, issuedAt, expiresAt, TokenType.ACCESS, ipAddress, deviceInfo, jti);

        logger.info("Access token generated for user: {} from IP: {}", user.getUsername(), ipAddress);
        return accessToken;
    }

    public String generateRefreshToken(SecurityUser user, String ipAddress, String deviceInfo, LocalDateTime expiresAt) {
        LocalDateTime issuedAt = LocalDateTime.now();
        String jti = UUID.randomUUID().toString();

        try {
            tokenRepository.deleteBySecurityUserAndTokenType(user, TokenType.REFRESH);
            tokenRepository.flush();
            logger.debug("Deleted existing REFRESH tokens for user: {}", user.getUsername());
        } catch (Exception e) {
            logger.warn("Failed to delete existing REFRESH tokens for user: {}", user.getUsername(), e);
        }

        String refreshToken = generateToken(user, getRefreshSecret(), issuedAt, expiresAt, false, jti);
        saveToken(user, refreshToken, issuedAt, expiresAt, TokenType.REFRESH, ipAddress, deviceInfo, jti);

        logger.info("Refresh token generated for user: {} from IP: {}", user.getUsername(), ipAddress);
        return refreshToken;
    }

    private String generateToken(SecurityUser user, String secret, LocalDateTime issuedAt,
                                 LocalDateTime expiresAt, boolean includeClaims, String jti) {
        Date issued = Date.from(issuedAt.atZone(ZoneId.systemDefault()).toInstant());
        Date expiration = Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant());

        JwtBuilder jwtBuilder = Jwts.builder()
                .subject(user.getUsername())
                .issuedAt(issued)
                .expiration(expiration)
                .id(jti) // JWT ID
                .issuer("CityCard-API") // Token'ı kim oluşturdu
                .audience().add("CityCard-Client") // Token kimler için
                .and()
                .signWith(getSignSecretKey(secret), Jwts.SIG.HS512); // Güncellenmiş yöntem

        if (includeClaims) {
            jwtBuilder.claim("userNumber", user.getUserNumber())
                    .claim("role", user.getRoles())
                    .claim("tokenType", "access")
                    .claim("version", "1.0"); // Token version
        } else {
            jwtBuilder.claim("tokenType", "refresh")
                    .claim("version", "1.0");
        }

        return jwtBuilder.compact();
    }

    private SecretKey getSignSecretKey(String secret) {
        // Secret'in yeterince güçlü olduğundan emin ol
        if (secret.length() < 64) {
            logger.warn("JWT secret too short, using extended version");
            secret = secret + generateSecureSecret();
        }

        byte[] keyBytes = Decoders.BASE64.decode(Base64.getEncoder().encodeToString(secret.getBytes()));
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private void saveToken(SecurityUser user, String tokenValue, LocalDateTime issuedAt,
                           LocalDateTime expiresAt, TokenType tokenType, String ipAddress,
                           String deviceInfo, String jti) {

        try {
            Token token = Token.builder()
                    .tokenValue(tokenValue)
                    .securityUser(user)
                    .tokenType(tokenType)
                    .issuedAt(issuedAt)
                    .expiresAt(expiresAt)
                    .ipAddress(ipAddress)
                    .deviceInfo(deviceInfo)
                    .isValid(true)
                    .jti(jti) // JWT ID'yi de kaydet
                    .build();

            tokenRepository.save(token);
            logger.debug("Token saved to database for user: {} with type: {}", user.getUsername(), tokenType);

        } catch (Exception e) {
            logger.error("Failed to save token for user: {} with type: {}", user.getUsername(), tokenType, e);

            try {
                tokenRepository.deleteBySecurityUserAndTokenType(user, tokenType);
                tokenRepository.flush();

                Token token = Token.builder()
                        .tokenValue(tokenValue)
                        .securityUser(user)
                        .tokenType(tokenType)
                        .issuedAt(issuedAt)
                        .expiresAt(expiresAt)
                        .ipAddress(ipAddress)
                        .deviceInfo(deviceInfo)
                        .isValid(true)
                        .jti(jti)
                        .build();

                tokenRepository.save(token);
                logger.info("Token saved successfully on retry for user: {} with type: {}", user.getUsername(), tokenType);

            } catch (Exception retryException) {
                logger.error("Failed to save token even after retry for user: {} with type: {}",
                        user.getUsername(), tokenType, retryException);
                throw new RuntimeException("Token save failed after retry", retryException);
            }
        }
    }

    public boolean validateToken(String token, String secret) throws TokenIsExpiredException, TokenNotFoundException {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSignSecretKey(secret))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            Optional<Token> tokenEntity = tokenRepository.findByTokenValue(token);

            if (tokenEntity.isEmpty() || !tokenEntity.get().isValid()) {
                logger.warn("Token not found in database or invalidated: {}", token.substring(0, 20) + "...");
                throw new TokenNotFoundException();
            }

            Token dbToken = tokenEntity.get();

            if (dbToken.getExpiresAt().isBefore(LocalDateTime.now())) {
                logger.warn("Token expired for user: {}", dbToken.getSecurityUser().getUsername());
                tokenRepository.delete(dbToken);
                throw new TokenIsExpiredException();
            }

            String jwtId = claims.getId();
            if (jwtId == null || !jwtId.equals(dbToken.getJti())) {
                logger.error("JWT ID mismatch for token: {}", token.substring(0, 20) + "...");
                throw new TokenNotFoundException();
            }

            String version = (String) claims.get("version");
            if (!"1.0".equals(version)) {
                logger.warn("Outdated token version: {} for user: {}", version, dbToken.getSecurityUser().getUsername());
                throw new TokenNotFoundException();
            }

            dbToken.setLastUsedAt(LocalDateTime.now());
            tokenRepository.save(dbToken);

            return true;

        } catch (ExpiredJwtException e) {
            logger.warn("JWT token expired: {}", e.getMessage());
            throw new TokenIsExpiredException();
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token: {}", e.getMessage());
            throw new TokenNotFoundException();
        } catch (MalformedJwtException e) {
            logger.error("Malformed JWT token: {}", e.getMessage());
            throw new TokenNotFoundException();
        } catch (IllegalArgumentException e) {
            logger.error("JWT token compact of handler are invalid: {}", e.getMessage());
            throw new TokenNotFoundException();
        } catch (JwtException e) {
            logger.error("JWT validation failed: {}", e.getMessage());
            throw new TokenNotFoundException();
        }
    }

    public boolean validateRefreshToken(String token) throws TokenIsExpiredException, TokenNotFoundException {
        return validateToken(token, getRefreshSecret());
    }

    public boolean validateAccessToken(String token) throws TokenIsExpiredException, TokenNotFoundException {
        return validateToken(token, getAccessSecret());
    }

    public Claims getAccessTokenClaims(String token) {
        return getClaims(token, getAccessSecret());
    }

    public Claims getRefreshTokenClaims(String token) {
        return getClaims(token, getRefreshSecret());
    }

    public String extractUsernameFromToken(String token) {
        try {
            Claims claims = getClaims(token, getAccessSecret());
            return claims.getSubject();
        } catch (Exception e) {
            logger.error("Failed to extract username from token: {}", e.getMessage());
            return null;
        }
    }

    public Claims getClaims(@NonNull String token, @NonNull String secretKey) {
        return Jwts.parser()
                .verifyWith(getSignSecretKey(secretKey))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {
        Optional<Token> optionalToken = tokenRepository.findByTokenValue(token);
        if (optionalToken.isEmpty()) {
            logger.warn("Token not found in database: {}", token.substring(0, 20) + "...");
            return null;
        }

        Token dbToken = optionalToken.get();
        return dbToken.getSecurityUser().getUsername();
    }

    // Token'ı manuel olarak geçersiz kılma
    public void invalidateToken(String tokenValue) {
        Optional<Token> optionalToken = tokenRepository.findByTokenValue(tokenValue);
        if (optionalToken.isPresent()) {
            Token token = optionalToken.get();
            token.setValid(false);
            tokenRepository.save(token);
            logger.info("Token invalidated for user: {}", token.getSecurityUser().getUsername());
        }
    }

    // Kullanıcının tüm token'larını geçersiz kılma (logout all devices)
    public void invalidateAllUserTokens(Long userId) {
        tokenRepository.findAllBySecurityUserId(userId).forEach(token -> {
            token.setValid(false);
            tokenRepository.save(token);
        });
        logger.info("All tokens invalidated for user ID: {}", userId);
    }

    // Güvenli secret key üretme
    private String generateSecureSecret() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[64]; // 512 bit
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    // Token'ın kaç dk sonra expire olacağını döndürme
    public long getTokenExpirationMinutes(String token, TokenType tokenType) {
        try {
            String secret = tokenType == TokenType.ACCESS ? getAccessSecret() : getRefreshSecret();
            Claims claims = getClaims(token, secret);
            Date expiration = claims.getExpiration();
            long diffInMillies = expiration.getTime() - System.currentTimeMillis();
            return diffInMillies / (60 * 1000); // dakika cinsinden
        } catch (Exception e) {
            return 0;
        }
    }
}