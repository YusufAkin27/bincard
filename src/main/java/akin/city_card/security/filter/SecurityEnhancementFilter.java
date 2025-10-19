package akin.city_card.security.filter;

import akin.city_card.response.ResponseMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.List;
import java.util.regex.Pattern;

@Component
public class SecurityEnhancementFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(SecurityEnhancementFilter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Kötü niyetli payload'ları tespit etmek için pattern'lar
    private static final List<Pattern> SQL_INJECTION_PATTERNS = List.of(
            Pattern.compile("('|(\\-\\-)|(;)|(\\|)|(\\*)|(%))", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(union|select|insert|delete|update|drop|create|alter|exec|execute)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(script|javascript|vbscript|onload|onerror|onclick)", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> XSS_PATTERNS = List.of(
            Pattern.compile("<[^>]*script[^>]*>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<[^>]*iframe[^>]*>", Pattern.CASE_INSENSITIVE)
    );

    // Şüpheli User-Agent'lar
    private static final List<Pattern> SUSPICIOUS_USER_AGENTS = List.of(
            Pattern.compile("(bot|crawler|spider|scraper)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(sqlmap|nikto|nmap|masscan|zap)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(python|curl|wget|postman)(?!.*mobile)", Pattern.CASE_INSENSITIVE)
    );

    // Korunması gereken hassas endpoint'ler
    private static final List<String> SENSITIVE_PATHS = List.of(
            "/v1/api/admin",
            "/v1/api/super-admin",
            "/v1/api/auth",
            "/v1/api/user/password",
            "/v1/api/wallet"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
/*
        // 1. Request boyutu kontrolü
        if (isRequestTooLarge(request)) {
            blockRequest(response, "İstek boyutu çok büyük.");
            return;
        }

        // 2. Şüpheli User-Agent kontrolü
        if (isSuspiciousUserAgent(request)) {
            String userAgent = request.getHeader("User-Agent");
            logger.warn("Şüpheli User-Agent tespit edildi: {} from IP: {}",
                    userAgent, getClientIp(request));
            blockRequest(response, "Geçersiz istemci.");
            return;
        }

        // 3. Path traversal kontrolü
        if (hasPathTraversal(request)) {
            logger.warn("Path traversal denemesi tespit edildi: {} from IP: {}",
                    request.getRequestURI(), getClientIp(request));
            blockRequest(response, "Geçersiz istek formatı.");
            return;
        }

        // 4. SQL Injection ve XSS kontrolü
        if (hasMaliciousContent(request)) {
            logger.error("Kötü niyetli payload tespit edildi: {} from IP: {}",
                    request.getRequestURI(), getClientIp(request));
            blockRequest(response, "Güvenlik ihlali tespit edildi.");
            return;
        }

        // 5. Hassas endpoint'ler için ek kontroller
        if (isSensitivePath(request.getRequestURI())) {
            if (!hasValidSecurityHeaders(request)) {
                logger.warn("Hassas endpoint'e eksik security header ile erişim: {} from IP: {}",
                        request.getRequestURI(), getClientIp(request));
                // Bu durumda block etmek yerine warning log'u yeterli olabilir
            }
        }

        // 6. Brute force koruması için başarısız deneme sayacı
        if (isAuthenticationPath(request.getRequestURI())) {
            // Bu authentication filter'da handle edilecek
        }

        // Security header'ları ekle
        addSecurityHeaders(response);

buraları açmak gerek güvenlik için
 */
        filterChain.doFilter(request, response);
    }

    private boolean isRequestTooLarge(HttpServletRequest request) {
        String contentLength = request.getHeader("Content-Length");
        if (contentLength != null) {
            try {
                long length = Long.parseLong(contentLength);
                // 10MB limit (çok büyük dosya upload'ları için)
                return length > 10 * 1024 * 1024;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return false;
    }

    private boolean isSuspiciousUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null || userAgent.trim().isEmpty()) {
            return true; // User-Agent olmayan istekler şüpheli
        }

        return SUSPICIOUS_USER_AGENTS.stream()
                .anyMatch(pattern -> pattern.matcher(userAgent).find());
    }

    private boolean hasPathTraversal(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String queryString = request.getQueryString();

        // Path traversal pattern'ları
        String[] traversalPatterns = {
                "../", "..\\", "%2e%2e%2f", "%2e%2e%5c",
                "....//", "....\\\\", "%252e%252e%252f"
        };

        for (String pattern : traversalPatterns) {
            if (uri.contains(pattern) || (queryString != null && queryString.contains(pattern))) {
                return true;
            }
        }
        return false;
    }

    private boolean hasMaliciousContent(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String queryString = request.getQueryString();

        // URI kontrolü
        if (containsMaliciousPattern(uri)) {
            return true;
        }

        // Query string kontrolü
        if (queryString != null && containsMaliciousPattern(queryString)) {
            return true;
        }

        // Header kontrolü (özellikle Referer ve X-Forwarded-For)
        String referer = request.getHeader("Referer");
        if (referer != null && containsMaliciousPattern(referer)) {
            return true;
        }

        return false;
    }

    private boolean containsMaliciousPattern(String input) {
        if (input == null) return false;

        String decodedInput = java.net.URLDecoder.decode(input, java.nio.charset.StandardCharsets.UTF_8);

        // SQL Injection kontrolü
        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            if (pattern.matcher(decodedInput).find()) {
                return true;
            }
        }

        // XSS kontrolü
        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(decodedInput).find()) {
                return true;
            }
        }

        return false;
    }

    private boolean isSensitivePath(String path) {
        return SENSITIVE_PATHS.stream().anyMatch(path::startsWith);
    }

    private boolean hasValidSecurityHeaders(HttpServletRequest request) {
        // Önemli security header'larının varlığını kontrol et
        String contentType = request.getHeader("Content-Type");
        String origin = request.getHeader("Origin");

        // POST istekleri için Content-Type kontrolü
        if ("POST".equals(request.getMethod()) || "PUT".equals(request.getMethod())) {
            return contentType != null &&
                    (contentType.startsWith("application/json") ||
                            contentType.startsWith("multipart/form-data"));
        }

        return true;
    }

    private boolean isAuthenticationPath(String path) {
        return path.startsWith("/v1/api/auth/") ||
                path.contains("/login") ||
                path.contains("/verify");
    }

    private void addSecurityHeaders(HttpServletResponse response) {
        // XSS Protection
        response.setHeader("X-XSS-Protection", "1; mode=block");

        // Content Type Options
        response.setHeader("X-Content-Type-Options", "nosniff");

        // Frame Options
        response.setHeader("X-Frame-Options", "DENY");

        // Referrer Policy
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // Content Security Policy
        response.setHeader("Content-Security-Policy",
                "default-src 'self'; " +
                        "script-src 'self' 'unsafe-inline'; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data: https:; " +
                        "font-src 'self'; " +
                        "connect-src 'self'; " +
                        "frame-ancestors 'none';"
        );

        // Permissions Policy
        response.setHeader("Permissions-Policy",
                "geolocation=(), microphone=(), camera=(), payment=(), usb=()");
    }

    private String getClientIp(HttpServletRequest request) {
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

    private void blockRequest(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json;charset=UTF-8");

        ResponseMessage responseMessage = new ResponseMessage(message, false);
        String json = objectMapper.writeValueAsString(responseMessage);
        response.getWriter().write(json);
    }
}