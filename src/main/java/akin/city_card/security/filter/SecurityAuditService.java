package akin.city_card.security.filter;

import akin.city_card.security.entity.SecurityAuditLog;
import akin.city_card.security.entity.SecurityEventType;
import akin.city_card.security.repository.SecurityAuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class SecurityAuditService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityAuditService.class);

    private final SecurityAuditLogRepository auditLogRepository;

    @Value("${security.audit.enabled:true}")
    private boolean auditEnabled;

    @Value("${security.audit.log-sensitive-paths:true}")
    private boolean logSensitivePaths;

    // Suspicious activity tracking
    private final Map<String, Integer> failedLoginAttempts = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lastFailedLoginTime = new ConcurrentHashMap<>();

    @Async
    public void logSecurityEvent(SecurityEventType eventType, String username,
                                 HttpServletRequest request, String details) {
        if (!auditEnabled) return;

        try {
            String ipAddress = getClientIp(request);
            String userAgent = request != null ? request.getHeader("User-Agent") : null;
            String requestUri = request != null ? request.getRequestURI() : null;
            String method = request != null ? request.getMethod() : null;

            SecurityAuditLog auditLog = SecurityAuditLog.builder()
                    .eventType(eventType)
                    .username(username)
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .requestUri(requestUri)
                    .httpMethod(method)
                    .eventDetails(details)
                    .timestamp(LocalDateTime.now())
                    .success(isSuccessEvent(eventType))
                    .build();

            auditLogRepository.save(auditLog);

            // Suspicious activity detection
            if (eventType == SecurityEventType.LOGIN_FAILED && ipAddress != null) {
                trackFailedLogin(ipAddress, username);
            } else if (eventType == SecurityEventType.LOGIN_SUCCESS && ipAddress != null) {
                clearFailedLoginAttempts(ipAddress);
            }

            logger.info("Security audit logged: {} - {} - {} - {}",
                    eventType, username, ipAddress, details);

        } catch (Exception e) {
            logger.error("Failed to log security audit event", e);
        }
    }

    // Overloaded method for cases where we have IP but no HttpServletRequest
    @Async
    public void logSecurityEvent(SecurityEventType eventType, String username,
                                 String ipAddress, String details) {
        if (!auditEnabled) return;

        try {
            SecurityAuditLog auditLog = SecurityAuditLog.builder()
                    .eventType(eventType)
                    .username(username)
                    .ipAddress(ipAddress)
                    .userAgent(null)
                    .requestUri(null)
                    .httpMethod(null)
                    .eventDetails(details)
                    .timestamp(LocalDateTime.now())
                    .success(isSuccessEvent(eventType))
                    .build();

            auditLogRepository.save(auditLog);

            // Suspicious activity detection
            if (eventType == SecurityEventType.LOGIN_FAILED && ipAddress != null) {
                trackFailedLogin(ipAddress, username);
            } else if (eventType == SecurityEventType.LOGIN_SUCCESS && ipAddress != null) {
                clearFailedLoginAttempts(ipAddress);
            }

            logger.info("Security audit logged: {} - {} - {} - {}",
                    eventType, username, ipAddress, details);

        } catch (Exception e) {
            logger.error("Failed to log security audit event", e);
        }
    }

    @Async
    public void logSuspiciousActivity(String ipAddress, String username, String activity,
                                      String details, HttpServletRequest request) {
        SecurityAuditLog auditLog = SecurityAuditLog.builder()
                .eventType(SecurityEventType.SUSPICIOUS_ACTIVITY)
                .username(username)
                .ipAddress(ipAddress)
                .userAgent(request != null ? request.getHeader("User-Agent") : null)
                .requestUri(request != null ? request.getRequestURI() : null)
                .httpMethod(request != null ? request.getMethod() : null)
                .eventDetails(String.format("Activity: %s, Details: %s", activity, details))
                .timestamp(LocalDateTime.now())
                .success(false)
                .severity("HIGH")
                .build();

        auditLogRepository.save(auditLog);

        logger.warn("Suspicious activity detected: {} - {} - {} - {}",
                activity, username, ipAddress, details);
    }

    public void logLoginSuccess(String username, HttpServletRequest request) {
        logSecurityEvent(SecurityEventType.LOGIN_SUCCESS, username, request,
                "User successfully logged in");
        String ipAddress = getClientIp(request);
        if (ipAddress != null) {
            clearFailedLoginAttempts(ipAddress);
        }
    }

    public void logLoginFailure(String username, HttpServletRequest request, String reason) {
        logSecurityEvent(SecurityEventType.LOGIN_FAILED, username, request,
                "Login failed: " + reason);
        String ipAddress = getClientIp(request);
        if (ipAddress != null) {
            trackFailedLogin(ipAddress, username);
        }
    }

    public void logLogout(String username, HttpServletRequest request) {
        logSecurityEvent(SecurityEventType.LOGOUT, username, request,
                "User logged out");
    }

    public void logTokenRefresh(String username, HttpServletRequest request) {
        logSecurityEvent(SecurityEventType.TOKEN_REFRESH, username, request,
                "Access token refreshed");
    }

    public void logPasswordChange(String username, HttpServletRequest request) {
        logSecurityEvent(SecurityEventType.PASSWORD_CHANGE, username, request,
                "Password changed successfully");
    }

    public void logAccountLocked(String username, HttpServletRequest request, String reason) {
        logSecurityEvent(SecurityEventType.ACCOUNT_LOCKED, username, request,
                "Account locked: " + reason);
    }

    public void logPermissionDenied(String username, HttpServletRequest request, String resource) {
        logSecurityEvent(SecurityEventType.PERMISSION_DENIED, username, request,
                "Access denied to resource: " + resource);
    }

    public void logRateLimitExceeded(String identifier, HttpServletRequest request, String limitType) {
        logSecurityEvent(SecurityEventType.RATE_LIMIT_EXCEEDED, identifier, request,
                "Rate limit exceeded for: " + limitType);
    }

    public void logAdminAction(String adminUsername, HttpServletRequest request, String action) {
        logSecurityEvent(SecurityEventType.ADMIN_ACTION, adminUsername, request,
                "Admin action: " + action);
    }

    private void trackFailedLogin(String ipAddress, String username) {
        if (ipAddress == null || username == null) return;

        String key = ipAddress + ":" + username;
        failedLoginAttempts.merge(key, 1, Integer::sum);
        lastFailedLoginTime.put(key, LocalDateTime.now());

        int attempts = failedLoginAttempts.get(key);
        if (attempts >= 5) {
            logSuspiciousActivity(ipAddress, username, "MULTIPLE_FAILED_LOGINS",
                    String.format("Failed login attempts: %d", attempts), null);
        }
    }

    private void clearFailedLoginAttempts(String ipAddress) {
        if (ipAddress == null) return;

        failedLoginAttempts.entrySet().removeIf(entry -> entry.getKey().startsWith(ipAddress + ":"));
        lastFailedLoginTime.entrySet().removeIf(entry -> entry.getKey().startsWith(ipAddress + ":"));
    }

    public boolean isIpSuspicious(String ipAddress) {
        if (ipAddress == null) return false;

        // Check if IP has too many failed attempts recently
        long recentFailures = failedLoginAttempts.entrySet().stream()
                .filter(entry -> entry.getKey().startsWith(ipAddress + ":"))
                .filter(entry -> {
                    LocalDateTime lastFailure = lastFailedLoginTime.get(entry.getKey());
                    return lastFailure != null && lastFailure.isAfter(LocalDateTime.now().minusMinutes(15));
                })
                .mapToInt(Map.Entry::getValue)
                .sum();

        return recentFailures >= 10;
    }

    public List<SecurityAuditLog> getRecentSuspiciousActivities(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return auditLogRepository.findSuspiciousActivitiesSince(since);
    }

    public List<SecurityAuditLog> getFailedLoginsForIp(String ipAddress, int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return auditLogRepository.findFailedLoginsByIpSince(ipAddress, since);
    }

    public List<SecurityAuditLog> getUserActivityHistory(String username, int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        return auditLogRepository.findUserActivitySince(username, since);
    }

    private boolean isSuccessEvent(SecurityEventType eventType) {
        return switch (eventType) {
            case LOGIN_SUCCESS, LOGOUT, TOKEN_REFRESH, PASSWORD_CHANGE -> true;
            case LOGIN_FAILED, ACCOUNT_LOCKED, PERMISSION_DENIED,
                 RATE_LIMIT_EXCEEDED, SUSPICIOUS_ACTIVITY -> false;
            default -> true;
        };
    }

    /**
     * Null-safe method to extract client IP from request
     */
    private String getClientIp(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }

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

        String remoteAddr = request.getRemoteAddr();
        return remoteAddr != null ? remoteAddr : "unknown";
    }

    public void cleanupOldAuditLogs(int daysToKeep) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(daysToKeep);
        int deletedCount = auditLogRepository.deleteOldAuditLogs(cutoffDate);
        logger.info("Cleaned up {} old audit log entries", deletedCount);
    }
}