package akin.city_card.security.filter;

import akin.city_card.response.ResponseMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitFilter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Farklı endpoint türleri için farklı bucket'lar
    private final Map<String, Bucket> authBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> generalBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> passwordBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> verificationBuckets = new ConcurrentHashMap<>();

    // Kritik authentication endpoint'leri - Çok sıkı limit
    private static final List<String> AUTH_PATHS = List.of(
            "/v1/api/auth/login",
            "/v1/api/auth/admin-login",
            "/v1/api/auth/superadmin-login",
            "/v1/api/auth/phone-verify"
    );

    // Şifre sıfırlama endpoint'leri - Çok sıkı limit
    private static final List<String> PASSWORD_PATHS = List.of(
            "/v1/api/user/password/forgot",
            "/v1/api/user/password/reset",
            "/v1/api/user/password/verify-code"
    );

    // Doğrulama kodu endpoint'leri - Sıkı limit
    private static final List<String> VERIFICATION_PATHS = List.of(
            "/v1/api/user/verify/phone/resend",
            "/v1/api/user/verify/phone",
            "/v1/api/user/verify/email/send",
            "/v1/api/user/email-verify"
    );

    // Genel korumalı endpoint'ler - Orta düzey limit
    private static final List<String> GENERAL_PROTECTED_PATHS = List.of(
            "/v1/api/user/sign-up",
            "/v1/api/auth/refresh",
            "/v1/api/auth/refresh-login"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();
        String clientKey = generateClientKey(request);
/*
        RateLimitType limitType = determineRateLimitType(path);
        
        if (limitType != RateLimitType.NONE) {
            Bucket bucket = getBucketForType(clientKey, limitType);
            
            if (!bucket.tryConsume(1)) {
                handleRateLimit(response, limitType, clientKey, path, method);
                return;
            }
            
            // Rate limit header'ları ekle
            addRateLimitHeaders(response, bucket, limitType);
        }

rate limiti aç güvenlik için
 */
        filterChain.doFilter(request, response);
    }

    private String generateClientKey(HttpServletRequest request) {
        String ip = getClientIP(request);
        String userAgent = request.getHeader("User-Agent");
        String deviceId = request.getHeader("X-Device-ID");

        if (deviceId != null && !deviceId.trim().isEmpty()) {
            return ip + ":" + deviceId.substring(0, Math.min(deviceId.length(), 20));
        } else {
            String agentHash = userAgent != null ? String.valueOf(userAgent.hashCode()) : "unknown";
            return ip + ":" + agentHash;
        }
    }

    private RateLimitType determineRateLimitType(String path) {
        if (AUTH_PATHS.stream().anyMatch(path::startsWith)) {
            return RateLimitType.AUTH;
        }
        if (PASSWORD_PATHS.stream().anyMatch(path::startsWith)) {
            return RateLimitType.PASSWORD;
        }
        if (VERIFICATION_PATHS.stream().anyMatch(path::startsWith)) {
            return RateLimitType.VERIFICATION;
        }
        if (GENERAL_PROTECTED_PATHS.stream().anyMatch(path::startsWith)) {
            return RateLimitType.GENERAL;
        }
        return RateLimitType.NONE;
    }

    private Bucket getBucketForType(String clientKey, RateLimitType type) {
        return switch (type) {
            case AUTH -> authBuckets.computeIfAbsent(clientKey, k -> createAuthBucket());
            case PASSWORD -> passwordBuckets.computeIfAbsent(clientKey, k -> createPasswordBucket());
            case VERIFICATION -> verificationBuckets.computeIfAbsent(clientKey, k -> createVerificationBucket());
            case GENERAL -> generalBuckets.computeIfAbsent(clientKey, k -> createGeneralBucket());
            default -> throw new IllegalStateException("Unexpected rate limit type: " + type);
        };
    }

    private Bucket createAuthBucket() {
        // Auth: 5 deneme / 5 dakika, sonra 3 deneme / 15 dakika
        Bandwidth primary = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(5)));
        Bandwidth secondary = Bandwidth.classic(3, Refill.intervally(3, Duration.ofMinutes(15)));
        return Bucket4j.builder()
                .addLimit(primary)
                .addLimit(secondary)
                .build();
    }

    private Bucket createPasswordBucket() {
        // Password: 3 deneme / 10 dakika
        Bandwidth limit = Bandwidth.classic(3, Refill.intervally(3, Duration.ofMinutes(10)));
        return Bucket4j.builder().addLimit(limit).build();
    }

    private Bucket createVerificationBucket() {
        // Verification: 10 deneme / 5 dakika
        Bandwidth limit = Bandwidth.classic(10, Refill.intervally(10, Duration.ofMinutes(5)));
        return Bucket4j.builder().addLimit(limit).build();
    }

    private Bucket createGeneralBucket() {
        // General: 20 deneme / 1 dakika
        Bandwidth limit = Bandwidth.classic(20, Refill.intervally(20, Duration.ofMinutes(1)));
        return Bucket4j.builder().addLimit(limit).build();
    }

    private void handleRateLimit(HttpServletResponse response, RateLimitType type,
                                 String clientKey, String path, String method) throws IOException {

        String message = switch (type) {
            case AUTH -> "Çok fazla giriş denemesi. Lütfen 5 dakika sonra tekrar deneyin.";
            case PASSWORD -> "Şifre sıfırlama işlemi için çok fazla deneme. 10 dakika bekleyin.";
            case VERIFICATION -> "Doğrulama kodu için çok fazla istek. 5 dakika bekleyin.";
            case GENERAL -> "Çok fazla istek gönderildi. 1 dakika bekleyin.";
            default -> "Rate limit aşıldı.";
        };

        long retryAfterSeconds = switch (type) {
            case AUTH -> 300; // 5 dakika
            case PASSWORD -> 600; // 10 dakika
            case VERIFICATION -> 300; // 5 dakika
            case GENERAL -> 60; // 1 dakika
            default -> 60;
        };

        logger.warn("Rate limit aşıldı. Type: {}, Client: {}, Path: {}, Method: {}",
                type, clientKey, path, method);

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        response.setContentType("application/json;charset=UTF-8");

        ResponseMessage responseMessage = new ResponseMessage(message, false);
        String json = objectMapper.writeValueAsString(responseMessage);
        response.getWriter().write(json);
    }

    private void addRateLimitHeaders(HttpServletResponse response, Bucket bucket, RateLimitType type) {
        long availableTokens = bucket.getAvailableTokens();
        response.setHeader("X-Rate-Limit-Remaining", String.valueOf(availableTokens));
        response.setHeader("X-Rate-Limit-Type", type.name());
    }

    private String getClientIP(HttpServletRequest request) {
        String[] headerNames = {
                "X-Forwarded-For",
                "X-Real-IP",
                "X-Originating-IP",
                "CF-Connecting-IP"
        };

        for (String headerName : headerNames) {
            String ip = request.getHeader(headerName);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }

    public enum RateLimitType {
        AUTH,
        PASSWORD,
        VERIFICATION,
        GENERAL,
        NONE
    }
}