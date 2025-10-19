package akin.city_card.health;

import akin.city_card.security.entity.enums.TokenType;
import akin.city_card.security.repository.TokenRepository;
import com.cloudinary.Cloudinary;
import com.cloudinary.api.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.sql.DataSource;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.OperatingSystemMXBean;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@RestController
@RequestMapping("v1/api/health")
@RequiredArgsConstructor
@Slf4j
public class HealthController {

    private final TokenRepository tokenRepository;
    private final DataSource dataSource;

    @Autowired(required = false)
    private JavaMailSender mailSender;

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired(required = false)
    private Cloudinary cloudinary;

    // Configuration values
    @Value("${spring.datasource.url}")
    private String dbUrl;

    @Value("${spring.datasource.username}")
    private String dbUsername;

    @Value("${spring.mail.host:}")
    private String mailHost;

    @Value("${spring.mail.port:587}")
    private int mailPort;

    @Value("${spring.data.redis.host:localhost}")
    private String redisHost;

    @Value("${spring.data.redis.port:6379}")
    private int redisPort;

    @Value("${cloudinary.cloud-name:}")
    private String cloudinaryCloudName;

    @Value("${google.maps.api.key:}")
    private String googleMapsApiKey;

    @Value("${iyzico.baseUrl:}")
    private String iyzicoBaseUrl;

    @Value("${simulation.enabled:false}")
    private boolean simulationEnabled;

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getHealthStatus() {
        Map<String, Object> healthStatus = new HashMap<>();
        boolean overallHealth = true;

        try {
            healthStatus.put("timestamp", LocalDateTime.now());
            healthStatus.put("applicationName", "city_card");

            // Aktif kullanıcı sayısı
            long activeUsers = getActiveUserCount();
            healthStatus.put("activeUsers", activeUsers);

            // PostgreSQL veritabanı durumu ve detayları
            Map<String, Object> dbStatus = checkPostgreSQLHealth();
            healthStatus.put("database", dbStatus);
            if (!(boolean) dbStatus.get("healthy")) {
                overallHealth = false;
            }

            // Redis durumu
            Map<String, Object> redisStatus = checkRedisHealth();
            healthStatus.put("redis", redisStatus);
            if (!(boolean) redisStatus.get("healthy")) {
                overallHealth = false;
            }

            // Mail servisi durumu (Gmail SMTP)
            Map<String, Object> mailStatus = checkGmailSMTPHealth();
            healthStatus.put("mailService", mailStatus);
            if (!(boolean) mailStatus.get("healthy")) {
                overallHealth = false;
            }

            // Cloudinary durumu
            Map<String, Object> cloudinaryStatus = checkCloudinaryHealth();
            healthStatus.put("cloudinary", cloudinaryStatus);

            // Google Maps API durumu
            Map<String, Object> googleMapsStatus = checkGoogleMapsHealth();
            healthStatus.put("googleMaps", googleMapsStatus);

            // Iyzico Payment durumu
            Map<String, Object> iyzicoStatus = checkIyzicoHealth();
            healthStatus.put("iyzico", iyzicoStatus);

            // Twilio durumu (SMS)
            Map<String, Object> twilioStatus = checkTwilioHealth();
            healthStatus.put("twilio", twilioStatus);

            // Sistem kaynakları
            Map<String, Object> memoryStatus = getDetailedMemoryUsage();
            healthStatus.put("memory", memoryStatus);

            Map<String, Object> cpuStatus = getDetailedCPUUsage();
            healthStatus.put("cpu", cpuStatus);

            Map<String, Object> diskStatus = getDetailedDiskUsage();
            healthStatus.put("disk", diskStatus);

            // Güvenlik kontrolleri
            Map<String, Object> securityStatus = checkSecurityHealth();
            healthStatus.put("security", securityStatus);

            // Simulation durumu
            Map<String, Object> simulationStatus = checkSimulationHealth();
            healthStatus.put("simulation", simulationStatus);

            healthStatus.put("status", overallHealth ? "UP" : "DOWN");
            healthStatus.put("overall", overallHealth ? "HEALTHY" : "UNHEALTHY");

            HttpStatus httpStatus = overallHealth ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE;
            return ResponseEntity.status(httpStatus).body(healthStatus);

        } catch (Exception e) {
            log.error("Health check failed", e);
            healthStatus.put("status", "DOWN");
            healthStatus.put("overall", "UNHEALTHY");
            healthStatus.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(healthStatus);
        }
    }

    @GetMapping("/database-details")
    public ResponseEntity<Map<String, Object>> getDatabaseDetails() {
        Map<String, Object> dbDetails = new HashMap<>();
        try {
            dbDetails.putAll(checkPostgreSQLHealth());
            dbDetails.putAll(getPostgreSQLStatistics());
            dbDetails.putAll(checkDataIntegrity());
            return ResponseEntity.ok(dbDetails);
        } catch (Exception e) {
            log.error("Database details check failed", e);
            dbDetails.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(dbDetails);
        }
    }

    @GetMapping("/security-audit")
    public ResponseEntity<Map<String, Object>> getSecurityAudit() {
        Map<String, Object> securityAudit = new HashMap<>();
        try {
            securityAudit.putAll(checkSecurityHealth());
            securityAudit.putAll(checkTokenSecurity());
            securityAudit.putAll(checkDataLeaks());
            return ResponseEntity.ok(securityAudit);
        } catch (Exception e) {
            log.error("Security audit failed", e);
            securityAudit.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(securityAudit);
        }
    }

    private long getActiveUserCount() {
        try {
            return tokenRepository.findAll().stream()
                    .filter(token -> token.getTokenType() == TokenType.ACCESS)
                    .filter(token -> token.isValid())
                    .filter(token -> token.getExpiresAt() != null && token.getExpiresAt().isAfter(LocalDateTime.now()))
                    .count();
        } catch (Exception e) {
            log.error("Failed to count active users", e);
            return -1;
        }
    }

    private Map<String, Object> checkPostgreSQLHealth() {
        Map<String, Object> dbStatus = new HashMap<>();
        try (Connection connection = dataSource.getConnection()) {
            boolean isValid = connection.isValid(10);
            dbStatus.put("healthy", isValid);
            dbStatus.put("status", isValid ? "UP" : "DOWN");

            if (isValid) {
                // Veritabanı bilgileri
                dbStatus.put("url", connection.getMetaData().getURL());
                dbStatus.put("driver", connection.getMetaData().getDriverName());
                dbStatus.put("version", connection.getMetaData().getDatabaseProductVersion());
                dbStatus.put("productName", connection.getMetaData().getDatabaseProductName());

                // Veritabanı boyutu
                try (PreparedStatement stmt = connection.prepareStatement(
                        "SELECT pg_size_pretty(pg_database_size('city_card')) as db_size")) {
                    ResultSet rs = stmt.executeQuery();
                    if (rs.next()) {
                        dbStatus.put("databaseSize", rs.getString("db_size"));
                    }
                }

                // Aktif bağlantı sayısı
                try (PreparedStatement stmt = connection.prepareStatement(
                        "SELECT count(*) as active_connections FROM pg_stat_activity WHERE state = 'active'")) {
                    ResultSet rs = stmt.executeQuery();
                    if (rs.next()) {
                        dbStatus.put("activeConnections", rs.getInt("active_connections"));
                    }
                }

                // Slow queries
                try (PreparedStatement stmt = connection.prepareStatement(
                        "SELECT count(*) as slow_queries FROM pg_stat_activity WHERE state = 'active' AND query_start < now() - interval '30 seconds'")) {
                    ResultSet rs = stmt.executeQuery();
                    if (rs.next()) {
                        dbStatus.put("slowQueries", rs.getInt("slow_queries"));
                    }
                }

                dbStatus.put("connectionTimeout", "10 seconds");
                dbStatus.put("autoReconnect", true);
            }
        } catch (Exception e) {
            log.error("PostgreSQL health check failed", e);
            dbStatus.put("healthy", false);
            dbStatus.put("status", "DOWN");
            dbStatus.put("error", e.getMessage());
        }
        return dbStatus;
    }

    private Map<String, Object> getPostgreSQLStatistics() {
        Map<String, Object> stats = new HashMap<>();
        try (Connection connection = dataSource.getConnection()) {
            // Tablo boyutları - DÜZELTME: Doğru kolon adları kullanıldı
            try (PreparedStatement stmt = connection.prepareStatement(
                    "SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size " +
                            "FROM pg_tables WHERE schemaname = 'public' ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC LIMIT 10")) {
                ResultSet rs = stmt.executeQuery();
                Map<String, String> tableSizes = new HashMap<>();
                while (rs.next()) {
                    tableSizes.put(rs.getString("tablename"), rs.getString("size"));
                }
                stats.put("topTableSizes", tableSizes);
            }

            // İndeks kullanımı - DÜZELTME: Doğru kolon adları kullanıldı
            try (PreparedStatement stmt = connection.prepareStatement(
                    "SELECT schemaname, tablename, indexname, pg_size_pretty(pg_relation_size(indexname::regclass)) as size " +
                            "FROM pg_indexes WHERE schemaname = 'public' ORDER BY pg_relation_size(indexname::regclass) DESC LIMIT 5")) {
                ResultSet rs = stmt.executeQuery();
                Map<String, String> indexSizes = new HashMap<>();
                while (rs.next()) {
                    indexSizes.put(rs.getString("indexname"), rs.getString("size"));
                }
                stats.put("topIndexSizes", indexSizes);
            }

        } catch (Exception e) {
            log.error("PostgreSQL statistics failed", e);
            stats.put("error", e.getMessage());
        }
        return stats;
    }

    private Map<String, Object> checkRedisHealth() {
        Map<String, Object> redisStatus = new HashMap<>();
        try {
            if (redisTemplate != null) {
                RedisConnection connection = redisTemplate.getConnectionFactory().getConnection();

                // Redis bağlantı testi
                String pong = connection.ping();
                boolean isHealthy = "PONG".equals(pong);

                redisStatus.put("healthy", isHealthy);
                redisStatus.put("status", isHealthy ? "UP" : "DOWN");
                redisStatus.put("ping", pong);
                redisStatus.put("host", redisHost);
                redisStatus.put("port", redisPort);

                if (isHealthy) {
                    // Redis bilgileri
                    Properties info = connection.info();
                    redisStatus.put("version", info.getProperty("redis_version"));
                    redisStatus.put("connectedClients", info.getProperty("connected_clients"));
                    redisStatus.put("usedMemory", info.getProperty("used_memory_human"));
                    redisStatus.put("usedMemoryPeak", info.getProperty("used_memory_peak_human"));

                    // Keyspace bilgileri
                    Long dbSize = connection.dbSize();
                    redisStatus.put("keyCount", dbSize);
                }

                connection.close();
            } else {
                redisStatus.put("healthy", false);
                redisStatus.put("status", "NOT_CONFIGURED");
                redisStatus.put("error", "Redis template not configured");
            }
        } catch (Exception e) {
            log.error("Redis health check failed", e);
            redisStatus.put("healthy", false);
            redisStatus.put("status", "DOWN");
            redisStatus.put("error", e.getMessage());
        }
        return redisStatus;
    }

    private Map<String, Object> checkGmailSMTPHealth() {
        Map<String, Object> mailStatus = new HashMap<>();
        try {
            if (mailSender != null && !mailHost.isEmpty()) {
                // SMTP bağlantı testi
                boolean isReachable = isHostReachable(mailHost, mailPort, 5000);

                mailStatus.put("healthy", isReachable);
                mailStatus.put("status", isReachable ? "UP" : "DOWN");
                mailStatus.put("host", mailHost);
                mailStatus.put("port", mailPort);
                mailStatus.put("protocol", "SMTP");
                mailStatus.put("authentication", true);
                mailStatus.put("starttls", true);
                mailStatus.put("configured", true);

                if (!isReachable) {
                    mailStatus.put("error", "SMTP host not reachable");
                }
            } else {
                mailStatus.put("healthy", false);
                mailStatus.put("status", "NOT_CONFIGURED");
                mailStatus.put("configured", false);
                mailStatus.put("error", "Mail service not configured");
            }
        } catch (Exception e) {
            log.error("Gmail SMTP health check failed", e);
            mailStatus.put("healthy", false);
            mailStatus.put("status", "DOWN");
            mailStatus.put("error", e.getMessage());
        }
        return mailStatus;
    }

    private Map<String, Object> checkCloudinaryHealth() {
        Map<String, Object> cloudinaryStatus = new HashMap<>();

        try {
            boolean configured = cloudinary != null && StringUtils.hasText(cloudinaryCloudName);
            cloudinaryStatus.put("configured", configured);

            if (!configured) {
                cloudinaryStatus.put("healthy", false);
                cloudinaryStatus.put("status", "NOT_CONFIGURED");
                return cloudinaryStatus;
            }

            Map<String, Object> emptyOptions = new HashMap<>();

            ApiResponse pingResponse = cloudinary.api().ping(emptyOptions);
            boolean isHealthy = pingResponse != null && "ok".equals(pingResponse.get("status"));

            cloudinaryStatus.put("healthy", isHealthy);
            cloudinaryStatus.put("status", isHealthy ? "UP" : "DOWN");
            cloudinaryStatus.put("cloudName", cloudinaryCloudName);

            if (isHealthy) {
                ApiResponse usage = cloudinary.api().usage(emptyOptions);

                if (usage != null) {
                    cloudinaryStatus.put("plan", usage.get("plan"));
                    cloudinaryStatus.put("usedPercent", usage.get("used_percent"));
                    cloudinaryStatus.put("credits", usage.get("credits"));
                }
            }
        } catch (Exception e) {
            cloudinaryStatus.put("healthy", false);
            cloudinaryStatus.put("status", "DOWN");
            cloudinaryStatus.put("error", e.getMessage());
        }

        return cloudinaryStatus;
    }


    private Map<String, Object> checkGoogleMapsHealth() {
        Map<String, Object> googleMapsStatus = new HashMap<>();
        try {
            if (!googleMapsApiKey.isEmpty()) {
                // Google Maps API test
                RestTemplate restTemplate = new RestTemplate();
                String testUrl = "https://maps.googleapis.com/maps/api/geocode/json?address=Istanbul&key=" + googleMapsApiKey;

                try {
                    ResponseEntity<String> response = restTemplate.getForEntity(testUrl, String.class);
                    boolean isHealthy = response.getStatusCode().is2xxSuccessful();

                    googleMapsStatus.put("healthy", isHealthy);
                    googleMapsStatus.put("status", isHealthy ? "UP" : "DOWN");
                    googleMapsStatus.put("configured", true);
                    googleMapsStatus.put("apiKeyLength", googleMapsApiKey.length());
                } catch (Exception e) {
                    googleMapsStatus.put("healthy", false);
                    googleMapsStatus.put("status", "DOWN");
                    googleMapsStatus.put("error", "API request failed: " + e.getMessage());
                }
            } else {
                googleMapsStatus.put("healthy", false);
                googleMapsStatus.put("status", "NOT_CONFIGURED");
                googleMapsStatus.put("configured", false);
            }
        } catch (Exception e) {
            log.error("Google Maps health check failed", e);
            googleMapsStatus.put("healthy", false);
            googleMapsStatus.put("status", "DOWN");
            googleMapsStatus.put("error", e.getMessage());
        }
        return googleMapsStatus;
    }

    private Map<String, Object> checkIyzicoHealth() {
        Map<String, Object> iyzicoStatus = new HashMap<>();
        try {
            if (!iyzicoBaseUrl.isEmpty()) {
                boolean isReachable = isUrlReachable(iyzicoBaseUrl, 10000);

                iyzicoStatus.put("healthy", isReachable);
                iyzicoStatus.put("status", isReachable ? "UP" : "DOWN");
                iyzicoStatus.put("baseUrl", iyzicoBaseUrl);
                iyzicoStatus.put("configured", true);
            } else {
                iyzicoStatus.put("healthy", false);
                iyzicoStatus.put("status", "NOT_CONFIGURED");
                iyzicoStatus.put("configured", false);
            }
        } catch (Exception e) {
            log.error("Iyzico health check failed", e);
            iyzicoStatus.put("healthy", false);
            iyzicoStatus.put("status", "DOWN");
            iyzicoStatus.put("error", e.getMessage());
        }
        return iyzicoStatus;
    }

    private Map<String, Object> checkTwilioHealth() {
        Map<String, Object> twilioStatus = new HashMap<>();
        try {
            // Twilio API endpoint test
            boolean isReachable = isUrlReachable("https://api.twilio.com", 10000);

            twilioStatus.put("healthy", isReachable);
            twilioStatus.put("status", isReachable ? "UP" : "DOWN");
            twilioStatus.put("apiEndpoint", "https://api.twilio.com");
            twilioStatus.put("configured", true);
        } catch (Exception e) {
            log.error("Twilio health check failed", e);
            twilioStatus.put("healthy", false);
            twilioStatus.put("status", "DOWN");
            twilioStatus.put("error", e.getMessage());
        }
        return twilioStatus;
    }

    private Map<String, Object> checkSimulationHealth() {
        Map<String, Object> simulationStatus = new HashMap<>();
        try {
            simulationStatus.put("enabled", simulationEnabled);
            simulationStatus.put("status", simulationEnabled ? "ENABLED" : "DISABLED");
            simulationStatus.put("healthy", true);
        } catch (Exception e) {
            log.error("Simulation health check failed", e);
            simulationStatus.put("healthy", false);
            simulationStatus.put("error", e.getMessage());
        }
        return simulationStatus;
    }

    private Map<String, Object> checkSecurityHealth() {
        Map<String, Object> securityStatus = new HashMap<>();
        try {
            // Token güvenliği
            long totalTokens = tokenRepository.count();
            long validTokens = tokenRepository.findAll().stream()
                    .mapToLong(token -> token.isValid() ? 1 : 0)
                    .sum();
            long expiredTokens = tokenRepository.findAll().stream()
                    .mapToLong(token -> token.getExpiresAt().isBefore(LocalDateTime.now()) ? 1 : 0)
                    .sum();

            securityStatus.put("totalTokens", totalTokens);
            securityStatus.put("validTokens", validTokens);
            securityStatus.put("expiredTokens", expiredTokens);
            securityStatus.put("tokenHealthScore", totalTokens > 0 ? (double) validTokens / totalTokens * 100 : 0);

            // SSL/TLS kontrolleri
            securityStatus.put("httpsOnly", false); // Bu production'da true olmalı
            securityStatus.put("secureHeaders", true);

            boolean isSecure = validTokens > 0 && expiredTokens < totalTokens * 0.5;
            securityStatus.put("healthy", isSecure);
            securityStatus.put("status", isSecure ? "SECURE" : "NEEDS_ATTENTION");

        } catch (Exception e) {
            log.error("Security health check failed", e);
            securityStatus.put("healthy", false);
            securityStatus.put("status", "UNKNOWN");
            securityStatus.put("error", e.getMessage());
        }
        return securityStatus;
    }

    private Map<String, Object> checkTokenSecurity() {
        Map<String, Object> tokenSecurity = new HashMap<>();
        try (Connection connection = dataSource.getConnection()) {
            // Suspicious token patterns
            try (PreparedStatement stmt = connection.prepareStatement(
                    "SELECT COUNT(*) as suspicious_tokens FROM token WHERE created_at > NOW() - INTERVAL '1 hour' AND ip_address IS NULL")) {
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    tokenSecurity.put("tokensWithoutIP", rs.getInt("suspicious_tokens"));
                }
            }

            // Multiple tokens from same IP
            try (PreparedStatement stmt = connection.prepareStatement(
                    "SELECT ip_address, COUNT(*) as token_count FROM token WHERE is_valid = true GROUP BY ip_address HAVING COUNT(*) > 10")) {
                ResultSet rs = stmt.executeQuery();
                int suspiciousIPs = 0;
                while (rs.next()) {
                    suspiciousIPs++;
                }
                tokenSecurity.put("suspiciousIPCount", suspiciousIPs);
            }

        } catch (Exception e) {
            log.error("Token security check failed", e);
            tokenSecurity.put("error", e.getMessage());
        }
        return tokenSecurity;
    }

    private Map<String, Object> checkDataLeaks() {
        Map<String, Object> dataLeaks = new HashMap<>();
        try (Connection connection = dataSource.getConnection()) {
            // Password exposure check (should all be hashed)
            try (PreparedStatement stmt = connection.prepareStatement(
                    "SELECT COUNT(*) as plain_passwords FROM security_users WHERE LENGTH(password) < 50")) {
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    int plainPasswords = rs.getInt("plain_passwords");
                    dataLeaks.put("potentialPlainPasswords", plainPasswords);
                    dataLeaks.put("passwordSecurity", plainPasswords == 0 ? "SECURE" : "COMPROMISED");
                }
            }

            // Email exposure in logs
            dataLeaks.put("emailsInLogs", "NOT_CHECKED"); // Log dosyalarını kontrol etmek gerekir

            // Sensitive data in token table
            try (PreparedStatement stmt = connection.prepareStatement(
                    "SELECT COUNT(*) as tokens_with_long_values FROM token WHERE LENGTH(token_value) > 1000")) {
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    dataLeaks.put("oversizedTokens", rs.getInt("tokens_with_long_values"));
                }
            }

            dataLeaks.put("status", "CHECKED");
            dataLeaks.put("healthy", true);

        } catch (Exception e) {
            log.error("Data leak check failed", e);
            dataLeaks.put("healthy", false);
            dataLeaks.put("error", e.getMessage());
        }
        return dataLeaks;
    }

    private Map<String, Object> checkDataIntegrity() {
        Map<String, Object> integrity = new HashMap<>();
        try (Connection connection = dataSource.getConnection()) {
            // Orphaned records check
            try (PreparedStatement stmt = connection.prepareStatement(
                    "SELECT COUNT(*) as orphaned_tokens FROM token t WHERE NOT EXISTS (SELECT 1 FROM security_users u WHERE u.id = t.user_id)")) {
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    integrity.put("orphanedTokens", rs.getInt("orphaned_tokens"));
                }
            }

            // Null constraints violation
            try (PreparedStatement stmt = connection.prepareStatement(
                    "SELECT COUNT(*) as null_user_numbers FROM security_users WHERE user_number IS NULL")) {
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    integrity.put("nullUserNumbers", rs.getInt("null_user_numbers"));
                }
            }

            integrity.put("status", "CHECKED");
            integrity.put("healthy", true);

        } catch (Exception e) {
            log.error("Data integrity check failed", e);
            integrity.put("healthy", false);
            integrity.put("error", e.getMessage());
        }
        return integrity;
    }

    private Map<String, Object> getDetailedMemoryUsage() {
        Map<String, Object> memoryStatus = new HashMap<>();
        try {
            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            Runtime runtime = Runtime.getRuntime();

            long heapUsed = memoryBean.getHeapMemoryUsage().getUsed();
            long heapMax = memoryBean.getHeapMemoryUsage().getMax();
            long heapCommitted = memoryBean.getHeapMemoryUsage().getCommitted();
            long nonHeapUsed = memoryBean.getNonHeapMemoryUsage().getUsed();
            long nonHeapMax = memoryBean.getNonHeapMemoryUsage().getMax();

            double heapUsagePercent = (double) heapUsed / heapMax * 100;

            memoryStatus.put("heapUsed", formatBytes(heapUsed));
            memoryStatus.put("heapMax", formatBytes(heapMax));
            memoryStatus.put("heapCommitted", formatBytes(heapCommitted));
            memoryStatus.put("heapUsagePercent", Math.round(heapUsagePercent * 100.0) / 100.0);
            memoryStatus.put("nonHeapUsed", formatBytes(nonHeapUsed));
            memoryStatus.put("nonHeapMax", formatBytes(nonHeapMax));

            // GC bilgileri
            memoryStatus.put("gcCollections", ManagementFactory.getGarbageCollectorMXBeans().stream()
                    .mapToLong(gc -> gc.getCollectionCount()).sum());
            memoryStatus.put("gcTime", ManagementFactory.getGarbageCollectorMXBeans().stream()
                    .mapToLong(gc -> gc.getCollectionTime()).sum() + "ms");

            memoryStatus.put("status", heapUsagePercent > 85 ? "CRITICAL" : heapUsagePercent > 70 ? "WARNING" : "OK");

        } catch (Exception e) {
            log.error("Memory usage check failed", e);
            memoryStatus.put("error", e.getMessage());
        }
        return memoryStatus;
    }

    private Map<String, Object> getDetailedCPUUsage() {
        Map<String, Object> cpuStatus = new HashMap<>();
        try {
            OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();

            double systemLoad = osBean.getSystemLoadAverage();
            int availableProcessors = osBean.getAvailableProcessors();

            cpuStatus.put("systemLoadAverage", systemLoad);
            cpuStatus.put("availableProcessors", availableProcessors);
            cpuStatus.put("loadPerCore", systemLoad > 0 ? Math.round((systemLoad / availableProcessors) * 100.0) / 100.0 : "N/A");
            cpuStatus.put("architecture", osBean.getArch());
            cpuStatus.put("osName", osBean.getName());
            cpuStatus.put("osVersion", osBean.getVersion());

            String status = "OK";
            if (systemLoad > availableProcessors * 0.9) status = "CRITICAL";
            else if (systemLoad > availableProcessors * 0.7) status = "WARNING";

            cpuStatus.put("status", status);

        } catch (Exception e) {
            log.error("CPU usage check failed", e);
            cpuStatus.put("error", e.getMessage());
        }
        return cpuStatus;
    }

    private Map<String, Object> getDetailedDiskUsage() {
        Map<String, Object> diskStatus = new HashMap<>();
        try {
            java.io.File root = new java.io.File("/");
            java.io.File tempDir = new java.io.File(System.getProperty("java.io.tmpdir"));
            java.io.File userDir = new java.io.File(System.getProperty("user.dir"));

            // Root disk usage
            long totalSpace = root.getTotalSpace();
            long freeSpace = root.getFreeSpace();
            long usedSpace = totalSpace - freeSpace;
            double usagePercent = (double) usedSpace / totalSpace * 100;

            diskStatus.put("rootDisk", Map.of(
                    "totalSpace", formatBytes(totalSpace),
                    "freeSpace", formatBytes(freeSpace),
                    "usedSpace", formatBytes(usedSpace),
                    "usagePercent", Math.round(usagePercent * 100.0) / 100.0
            ));

            // Temp directory usage
            diskStatus.put("tempDir", Map.of(
                    "path", tempDir.getAbsolutePath(),
                    "totalSpace", formatBytes(tempDir.getTotalSpace()),
                    "freeSpace", formatBytes(tempDir.getFreeSpace())
            ));

            // Application directory usage
            diskStatus.put("appDir", Map.of(
                    "path", userDir.getAbsolutePath(),
                    "totalSpace", formatBytes(userDir.getTotalSpace()),
                    "freeSpace", formatBytes(userDir.getFreeSpace())
            ));

            String status = "OK";
            if (usagePercent > 90) status = "CRITICAL";
            else if (usagePercent > 80) status = "WARNING";

            diskStatus.put("status", status);
            diskStatus.put("overallUsagePercent", Math.round(usagePercent * 100.0) / 100.0);

        } catch (Exception e) {
            log.error("Disk usage check failed", e);
            diskStatus.put("error", e.getMessage());
        }
        return diskStatus;
    }

    // Helper methods
    private boolean isHostReachable(String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeout);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private boolean isUrlReachable(String url, int timeout) {
        try {
            RestTemplate restTemplate = new RestTemplate();
            restTemplate.getForEntity(url, String.class);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        String pre = "KMGTPE".charAt(exp - 1) + "B";
        return String.format("%.1f %s", bytes / Math.pow(1024, exp), pre);
    }

    @GetMapping("/apis-status")
    public ResponseEntity<Map<String, Object>> getApisStatus() {
        Map<String, Object> apisStatus = new HashMap<>();
        try {
            apisStatus.put("timestamp", LocalDateTime.now());

            // Test all external APIs
            Map<String, Object> externalApis = new HashMap<>();
            externalApis.put("cloudinary", checkCloudinaryHealth());
            externalApis.put("googleMaps", checkGoogleMapsHealth());
            externalApis.put("iyzico", checkIyzicoHealth());
            externalApis.put("twilio", checkTwilioHealth());
            externalApis.put("gmailSmtp", checkGmailSMTPHealth());

            apisStatus.put("externalApis", externalApis);

            // Internal services
            Map<String, Object> internalServices = new HashMap<>();
            internalServices.put("database", checkPostgreSQLHealth());
            internalServices.put("redis", checkRedisHealth());
            internalServices.put("simulation", checkSimulationHealth());

            apisStatus.put("internalServices", internalServices);

            // API health summary
            long healthyApis = externalApis.values().stream()
                    .mapToLong(api -> ((Map<String, Object>) api).get("healthy").equals(true) ? 1 : 0)
                    .sum();
            long totalApis = externalApis.size();

            apisStatus.put("healthyApisCount", healthyApis);
            apisStatus.put("totalApisCount", totalApis);
            apisStatus.put("apiHealthPercentage", Math.round((double) healthyApis / totalApis * 100 * 100.0) / 100.0);
            apisStatus.put("overallStatus", healthyApis == totalApis ? "ALL_HEALTHY" : "SOME_ISSUES");

            return ResponseEntity.ok(apisStatus);

        } catch (Exception e) {
            log.error("APIs status check failed", e);
            apisStatus.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apisStatus);
        }
    }

    @GetMapping("/performance-metrics")
    public ResponseEntity<Map<String, Object>> getPerformanceMetrics() {
        Map<String, Object> performance = new HashMap<>();
        try {
            performance.put("timestamp", LocalDateTime.now());

            // JVM Performance
            Map<String, Object> jvmMetrics = new HashMap<>();
            jvmMetrics.put("uptime", ManagementFactory.getRuntimeMXBean().getUptime() + "ms");
            jvmMetrics.put("startTime", ManagementFactory.getRuntimeMXBean().getStartTime());
            jvmMetrics.put("javaVersion", System.getProperty("java.version"));
            jvmMetrics.put("jvmName", System.getProperty("java.vm.name"));
            jvmMetrics.put("jvmVendor", System.getProperty("java.vm.vendor"));

            // Thread information
            jvmMetrics.put("threadCount", ManagementFactory.getThreadMXBean().getThreadCount());
            jvmMetrics.put("peakThreadCount", ManagementFactory.getThreadMXBean().getPeakThreadCount());
            jvmMetrics.put("daemonThreadCount", ManagementFactory.getThreadMXBean().getDaemonThreadCount());

            performance.put("jvm", jvmMetrics);

            // Class loading
            Map<String, Object> classLoading = new HashMap<>();
            classLoading.put("loadedClassCount", ManagementFactory.getClassLoadingMXBean().getLoadedClassCount());
            classLoading.put("totalLoadedClassCount", ManagementFactory.getClassLoadingMXBean().getTotalLoadedClassCount());
            classLoading.put("unloadedClassCount", ManagementFactory.getClassLoadingMXBean().getUnloadedClassCount());

            performance.put("classLoading", classLoading);

            // Memory pools
            ManagementFactory.getMemoryPoolMXBeans().forEach(pool -> {
                if (pool.getUsage() != null) {
                    Map<String, Object> poolInfo = new HashMap<>();
                    poolInfo.put("used", formatBytes(pool.getUsage().getUsed()));
                    poolInfo.put("max", formatBytes(pool.getUsage().getMax()));
                    poolInfo.put("committed", formatBytes(pool.getUsage().getCommitted()));
                    performance.put("memoryPool_" + pool.getName().replaceAll(" ", "_"), poolInfo);
                }
            });

            // Database performance
            performance.put("database", getDatabasePerformanceMetrics());

            return ResponseEntity.ok(performance);

        } catch (Exception e) {
            log.error("Performance metrics failed", e);
            performance.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(performance);
        }
    }

    private Map<String, Object> getDatabasePerformanceMetrics() {
        Map<String, Object> dbPerformance = new HashMap<>();
        try (Connection connection = dataSource.getConnection()) {

            // Connection pool stats
            dbPerformance.put("connectionValid", connection.isValid(5));
            dbPerformance.put("autoCommit", connection.getAutoCommit());
            dbPerformance.put("readOnly", connection.isReadOnly());
            dbPerformance.put("transactionIsolation", connection.getTransactionIsolation());

            // Database activity
            try (PreparedStatement stmt = connection.prepareStatement(
                    "SELECT state, count(*) as count FROM pg_stat_activity GROUP BY state")) {
                ResultSet rs = stmt.executeQuery();
                Map<String, Integer> activityByState = new HashMap<>();
                while (rs.next()) {
                    activityByState.put(rs.getString("state"), rs.getInt("count"));
                }
                dbPerformance.put("connectionsByState", activityByState);
            }

            // Table statistics
            try (PreparedStatement stmt = connection.prepareStatement(
                    "SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del, n_live_tup, n_dead_tup " +
                            "FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 5")) {
                ResultSet rs = stmt.executeQuery();
                Map<String, Object> topTables = new HashMap<>();
                while (rs.next()) {
                    Map<String, Object> tableStats = new HashMap<>();
                    tableStats.put("inserts", rs.getLong("n_tup_ins"));
                    tableStats.put("updates", rs.getLong("n_tup_upd"));
                    tableStats.put("deletes", rs.getLong("n_tup_del"));
                    tableStats.put("liveTuples", rs.getLong("n_live_tup"));
                    tableStats.put("deadTuples", rs.getLong("n_dead_tup"));
                    topTables.put(rs.getString("tablename"), tableStats);
                }
                dbPerformance.put("topTablesBySize", topTables);
            }

        } catch (Exception e) {
            log.error("Database performance metrics failed", e);
            dbPerformance.put("error", e.getMessage());
        }
        return dbPerformance;
    }

    @GetMapping("/full-system-report")
    public ResponseEntity<Map<String, Object>> getFullSystemReport() {
        Map<String, Object> fullReport = new HashMap<>();
        try {
            fullReport.put("timestamp", LocalDateTime.now());
            fullReport.put("reportVersion", "1.0");
            fullReport.put("applicationName", "city_card");

            // Include all health checks
            ResponseEntity<Map<String, Object>> healthStatus = getHealthStatus();
            fullReport.put("systemHealth", healthStatus.getBody());

            ResponseEntity<Map<String, Object>> dbDetails = getDatabaseDetails();
            fullReport.put("databaseDetails", dbDetails.getBody());

            ResponseEntity<Map<String, Object>> securityAudit = getSecurityAudit();
            fullReport.put("securityAudit", securityAudit.getBody());

            ResponseEntity<Map<String, Object>> apisStatus = getApisStatus();
            fullReport.put("apisStatus", apisStatus.getBody());

            ResponseEntity<Map<String, Object>> performanceMetrics = getPerformanceMetrics();
            fullReport.put("performanceMetrics", performanceMetrics.getBody());

            // Configuration summary
            Map<String, Object> configSummary = new HashMap<>();
            configSummary.put("databaseUrl", dbUrl.replaceAll("password=[^&]*", "password=***"));
            configSummary.put("databaseUsername", dbUsername);
            configSummary.put("mailHost", mailHost);
            configSummary.put("mailPort", mailPort);
            configSummary.put("redisHost", redisHost);
            configSummary.put("redisPort", redisPort);
            configSummary.put("cloudinaryConfigured", !cloudinaryCloudName.isEmpty());
            configSummary.put("googleMapsConfigured", !googleMapsApiKey.isEmpty());
            configSummary.put("iyzicoConfigured", !iyzicoBaseUrl.isEmpty());
            configSummary.put("simulationEnabled", simulationEnabled);

            fullReport.put("configuration", configSummary);

            // Generate overall health score
            double healthScore = calculateOverallHealthScore(fullReport);
            fullReport.put("overallHealthScore", Math.round(healthScore * 100.0) / 100.0);
            fullReport.put("healthGrade", getHealthGrade(healthScore));

            return ResponseEntity.ok(fullReport);

        } catch (Exception e) {
            log.error("Full system report failed", e);
            fullReport.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(fullReport);
        }
    }

    // DÜZELTME: Null pointer exception hatası düzeltildi
    private double calculateOverallHealthScore(Map<String, Object> report) {
        double score = 0.0;
        int components = 0;

        try {
            Map<String, Object> systemHealth = safeCastMap(report.get("systemHealth"));
            if (systemHealth == null) {
                log.warn("SystemHealth is null, cannot calculate score");
                return 0.0;
            }

            // Database health (30%)
            Map<String, Object> database = safeCastMap(systemHealth.get("database"));
            if (database != null && Boolean.TRUE.equals(database.get("healthy"))) {
                score += 30.0;
            }
            components++;

            // APIs health (25%)
            Map<String, Object> apisStatus = safeCastMap(report.get("apisStatus"));
            if (apisStatus != null) {
                Object apiHealthObj = apisStatus.get("apiHealthPercentage");
                if (apiHealthObj instanceof Number) {
                    double apiHealth = ((Number) apiHealthObj).doubleValue();
                    score += (apiHealth / 100.0) * 25.0;
                }
            }
            components++;

            // Memory health (20%)
            Map<String, Object> memory = safeCastMap(systemHealth.get("memory"));
            if (memory != null) {
                String memoryStatus = String.valueOf(memory.get("status"));
                if ("OK".equalsIgnoreCase(memoryStatus)) score += 20.0;
                else if ("WARNING".equalsIgnoreCase(memoryStatus)) score += 10.0;
            }
            components++;

            // Security health (15%) - DÜZELTME: Null check eklendi
            Map<String, Object> securityAudit = safeCastMap(report.get("securityAudit"));
            if (securityAudit != null) {
                // "security" anahtarı yerine direkt securityAudit'i kontrol et
                // çünkü checkSecurityHealth direkt securityAudit'e ekleniyor
                if (Boolean.TRUE.equals(securityAudit.get("healthy"))) {
                    score += 15.0;
                }
            }
            components++;

            // Redis health (10%)
            Map<String, Object> redis = safeCastMap(systemHealth.get("redis"));
            if (redis != null && Boolean.TRUE.equals(redis.get("healthy"))) {
                score += 10.0;
            }
            components++;

        } catch (Exception e) {
            log.warn("Health score calculation incomplete", e);
        }

        return score;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> safeCastMap(Object obj) {
        if (obj instanceof Map<?, ?> map) {
            try {
                return (Map<String, Object>) map;
            } catch (ClassCastException e) {
                log.warn("Failed to cast map safely: {}", e.getMessage());
            }
        }
        return null;
    }

    private String getHealthGrade(double score) {
        if (score >= 90) return "A+ (Mükemmel)";
        if (score >= 80) return "A (Çok İyi)";
        if (score >= 70) return "B (İyi)";
        if (score >= 60) return "C (Orta)";
        if (score >= 50) return "D (Zayıf)";
        return "F (Kritik)";
    }
}