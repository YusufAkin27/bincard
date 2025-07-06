package akin.city_card.security.rateLimit;

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
    private final Map<String, Bucket> bucketCache = new ConcurrentHashMap<>();

    private static final List<String> RATE_LIMITED_PATHS = List.of(
            "/v1/api/auth/login",
            "/v1/api/auth/admin-login",
            "/v1/api/auth/superadmin-login",
            "/v1/api/auth/phone-verify",
            "/v1/api/user/verify/phone/resend",
            "/v1/api/user/password/reset",
            "/v1/api/user/password/verify-code",
            "/v1/api/user/password/forgot",
            "/v1/api/user/sign-up",
            "/v1/api/user/verify/phone"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        boolean shouldRateLimit = RATE_LIMITED_PATHS.stream().anyMatch(path::startsWith);

        if (shouldRateLimit) {
            String ip = getClientIP(request);
            String deviceId = request.getHeader("User-Agent"); // cihaz bilgisi

            String key = ip + ":" + (deviceId != null ? deviceId : "unknown");

            Bucket bucket = bucketCache.computeIfAbsent(key, this::createNewBucket);

            if (bucket.tryConsume(1)) {
                filterChain.doFilter(request, response);
            } else {
                logger.warn("Rate limit aşıldı. IP: {}, Device: {}", ip, deviceId);

                long waitForRefillSeconds = 2 * 60; // 2 dakika bekleme süresi

                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setHeader("Retry-After", String.valueOf(waitForRefillSeconds));
                response.setContentType("application/json;charset=UTF-8");

                ResponseMessage message = new ResponseMessage("Çok fazla istek gönderildi. Lütfen "
                        + (waitForRefillSeconds / 60) + " dakika sonra tekrar deneyin.", false);

                String json = objectMapper.writeValueAsString(message);
                response.getWriter().write(json);
            }

        } else {
            filterChain.doFilter(request, response);
        }
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty()){
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    private Bucket createNewBucket(String key) {
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1)));
        return Bucket4j.builder().addLimit(limit).build();
    }
}
