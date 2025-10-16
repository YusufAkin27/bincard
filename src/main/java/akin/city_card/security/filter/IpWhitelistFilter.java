package akin.city_card.security.filter;

import akin.city_card.response.ResponseMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class IpWhitelistFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(IpWhitelistFilter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    // application.yml'den IP'leri al
    @Value("${security.admin.allowed-ips}")
    private String adminAllowedIps;

    @Value("${security.superadmin.allowed-ips}")
    private String superAdminAllowedIps;

    // Admin ve SuperAdmin yolları
    private static final List<String> ADMIN_PATHS = List.of(
            "/v1/api/admin",
            "/v1/api/auth/admin-login"
    );

    private static final List<String> SUPERADMIN_PATHS = List.of(
            "/v1/api/super-admin",
            "/v1/api/auth/superadmin-login",
            "/v1/api/health"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String clientIp = getClientIp(request);

        // Admin path kontrolü
        if (isAdminPath(path)) {
            Set<String> allowedAdminIps = parseIpList(adminAllowedIps);
            if (!isIpAllowed(clientIp, allowedAdminIps)) {
                logger.warn("Admin path erişim engellendi. IP: {}, Path: {}", clientIp, path);
                blockRequest(response, "Admin paneline erişim yetkiniz bulunmamaktadır.");
                return;
            }
        }

        // SuperAdmin path kontrolü
        if (isSuperAdminPath(path)) {
            Set<String> allowedSuperAdminIps = parseIpList(superAdminAllowedIps);
            if (!isIpAllowed(clientIp, allowedSuperAdminIps)) {
                logger.error("SuperAdmin path erişim engellendi. IP: {}, Path: {}", clientIp, path);
                blockRequest(response, "Süper admin paneline erişim yetkiniz bulunmamaktadır.");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isAdminPath(String path) {
        return ADMIN_PATHS.stream().anyMatch(path::startsWith);
    }

    private boolean isSuperAdminPath(String path) {
        return SUPERADMIN_PATHS.stream().anyMatch(path::startsWith);
    }

    private String getClientIp(HttpServletRequest request) {
        // Çoklu proxy desteği
        String[] headerNames = {
                "X-Forwarded-For",
                "X-Real-IP",
                "X-Originating-IP",
                "CF-Connecting-IP", // Cloudflare
                "True-Client-IP"
        };

        for (String headerName : headerNames) {
            String ip = request.getHeader(headerName);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }

    private Set<String> parseIpList(String ipList) {
        if (ipList == null || ipList.trim().isEmpty()) {
            return Set.of("127.0.0.1", "::1"); // Default localhost
        }

        return Arrays.stream(ipList.split(","))
                .map(String::trim)
                .filter(ip -> !ip.isEmpty())
                .collect(Collectors.toSet());
    }

    private boolean isIpAllowed(String clientIp, Set<String> allowedIps) {
        // Exact match kontrolü
        if (allowedIps.contains(clientIp)) {
            return true;
        }

        // CIDR notation desteği (örn: 192.168.1.0/24)
        for (String allowedIp : allowedIps) {
            if (allowedIp.contains("/")) {
                if (isIpInCidr(clientIp, allowedIp)) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean isIpInCidr(String ip, String cidr) {
        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2) return false;

            String networkIp = parts[0];
            int prefixLength = Integer.parseInt(parts[1]);

            long ipLong = ipToLong(ip);
            long networkLong = ipToLong(networkIp);
            long mask = (0xFFFFFFFFL << (32 - prefixLength)) & 0xFFFFFFFFL;

            return (ipLong & mask) == (networkLong & mask);
        } catch (Exception e) {
            logger.error("CIDR parsing error for IP: {} and CIDR: {}", ip, cidr, e);
            return false;
        }
    }

    private long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IP: " + ip);

        long result = 0;
        for (int i = 0; i < 4; i++) {
            result = (result << 8) + Integer.parseInt(parts[i]);
        }
        return result;
    }

    private void blockRequest(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json;charset=UTF-8");

        ResponseMessage responseMessage = new ResponseMessage(message, false);
        String json = objectMapper.writeValueAsString(responseMessage);
        response.getWriter().write(json);
    }
}