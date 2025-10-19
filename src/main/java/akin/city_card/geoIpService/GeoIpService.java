package akin.city_card.geoIpService;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Duration;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class GeoIpService {

    private static final Logger logger = LoggerFactory.getLogger(GeoIpService.class);

    private static final String API_URL = "https://ipapi.co/%s/json/";
    private static final String CACHE_PREFIX = "geoip:";
    private static final String NULL_CACHE_VALUE = "NULL_RESULT";

    // Local/Private IP ranges
    private static final Set<String> LOCAL_IPS = Set.of(
            "127.0.0.1",
            "localhost",
            "0:0:0:0:0:0:0:1",
            "::1"
    );

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${app.geoip.cache.ttl-minutes:60}")
    private long cacheTtlMinutes;

    @Value("${app.geoip.cache.null-ttl-minutes:5}")
    private long nullCacheTtlMinutes;

    public GeoLocationData getGeoData(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) {
            logger.warn("IP address is null or empty");
            return null;
        }

        // Normalize IP address
        String normalizedIp = normalizeIpAddress(ipAddress);

        // Check if it's a local/private IP
        if (isLocalOrPrivateIp(normalizedIp)) {
            logger.debug("Local/Private IP detected: {}, returning default location", normalizedIp);
            return createDefaultGeoData();
        }

        String cacheKey = CACHE_PREFIX + normalizedIp;

        try {
            // 1. Check cache first
            String cachedValue = redisTemplate.opsForValue().get(cacheKey);
            if (cachedValue != null) {
                logger.debug("Cache hit for IP: {}", normalizedIp);

                // If it's a cached null result, return null
                if (NULL_CACHE_VALUE.equals(cachedValue)) {
                    logger.debug("Cached null result for IP: {}", normalizedIp);
                    return null;
                }

                try {
                    return objectMapper.readValue(cachedValue, GeoLocationData.class);
                } catch (Exception e) {
                    logger.warn("Failed to deserialize cached data for IP: {}, removing from cache", normalizedIp, e);
                    redisTemplate.delete(cacheKey);
                }
            }

            // 2. Fetch from API if not in cache
            GeoLocationData geoData = fetchFromApi(normalizedIp);

            // 3. Cache the result (even if null)
            cacheResult(cacheKey, geoData);

            return geoData;

        } catch (Exception e) {
            logger.error("Unexpected exception in GeoIpService for IP: {}", normalizedIp, e);
        }

        return null;
    }

    private String normalizeIpAddress(String ipAddress) {
        String normalized = ipAddress.trim();

        // Convert IPv6 localhost to IPv4
        if ("0:0:0:0:0:0:0:1".equals(normalized) || "::1".equals(normalized)) {
            return "127.0.0.1";
        }

        return normalized;
    }

    private boolean isLocalOrPrivateIp(String ipAddress) {
        if (LOCAL_IPS.contains(ipAddress)) {
            return true;
        }

        // Check for private IP ranges
        if (ipAddress.startsWith("192.168.") ||
                ipAddress.startsWith("10.") ||
                (ipAddress.startsWith("172.") && isInRange172(ipAddress))) {
            return true;
        }

        return false;
    }

    private boolean isInRange172(String ipAddress) {
        try {
            String[] parts = ipAddress.split("\\.");
            if (parts.length >= 2) {
                int secondOctet = Integer.parseInt(parts[1]);
                return secondOctet >= 16 && secondOctet <= 31;
            }
        } catch (NumberFormatException e) {
            // Ignore parsing errors
        }
        return false;
    }

    private GeoLocationData createDefaultGeoData() {
        GeoLocationData defaultData = new GeoLocationData();
        defaultData.setCity("Unknown");
        defaultData.setRegion("Unknown");
        defaultData.setCountryName("Unknown");
        defaultData.setTimezone("UTC");
        defaultData.setOrg("Local Network");
        return defaultData;
    }

    private GeoLocationData fetchFromApi(String ipAddress) {
        String url = String.format(API_URL, ipAddress);
        logger.debug("Fetching GeoIP data from API for IP: {}", ipAddress);

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            request.addHeader("Accept", "application/json");
            request.addHeader("User-Agent", "CityCard-GeoIP-Service/1.0");

            try (CloseableHttpResponse response = httpClient.execute(request)) {
                int statusCode = response.getCode();
                if (statusCode != 200) {
                    logger.error("GeoIP API returned non-OK status: {} for IP: {}", statusCode, ipAddress);
                    return null;
                }

                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    logger.error("GeoIP API response entity is null for IP: {}", ipAddress);
                    return null;
                }

                String result = EntityUtils.toString(entity);
                GeoLocationData geoData = objectMapper.readValue(result, GeoLocationData.class);

                if (isValidGeoData(geoData)) {
                    logger.info("Valid GeoIP data received for IP {}: city={}, region={}, country={}, timezone={}, org={}",
                            ipAddress,
                            geoData.getCity(),
                            geoData.getRegion(),
                            geoData.getCountryName(),
                            geoData.getTimezone(),
                            geoData.getOrg());
                    return geoData;
                } else {
                    logger.warn("Invalid or empty GeoIP data received for IP: {}", ipAddress);
                    return null;
                }
            }
        } catch (ParseException e) {
            logger.error("Failed to parse GeoIP API response for IP: {}", ipAddress, e);
        } catch (IOException e) {
            logger.error("IOException during GeoIP data fetch for IP: {}", ipAddress, e);
        } catch (Exception e) {
            logger.error("Unexpected exception during API fetch for IP: {}", ipAddress, e);
        }

        return null;
    }

    private boolean isValidGeoData(GeoLocationData geoData) {
        if (geoData == null) return false;

        // Check if at least one important field has valid data
        return hasValue(geoData.getCity()) ||
                hasValue(geoData.getRegion()) ||
                hasValue(geoData.getCountryName()) ||
                hasValue(geoData.getTimezone());
    }

    private boolean hasValue(String value) {
        return value != null && !value.trim().isEmpty() && !"null".equalsIgnoreCase(value);
    }

    private void cacheResult(String cacheKey, GeoLocationData geoData) {
        try {
            if (geoData != null) {
                // Cache valid data
                String jsonData = objectMapper.writeValueAsString(geoData);
                redisTemplate.opsForValue().set(cacheKey, jsonData, Duration.ofMinutes(cacheTtlMinutes));
                logger.debug("GeoIP data cached for key: {}", cacheKey);
            } else {
                // Cache null result with shorter TTL to avoid repeated API calls
                redisTemplate.opsForValue().set(cacheKey, NULL_CACHE_VALUE, Duration.ofMinutes(nullCacheTtlMinutes));
                logger.debug("Null result cached for key: {}", cacheKey);
            }
        } catch (Exception e) {
            logger.warn("Failed to cache GeoIP data for key: {}", cacheKey, e);
        }
    }

    // Method to manually clear cache for an IP
    public void clearCache(String ipAddress) {
        if (ipAddress != null && !ipAddress.isBlank()) {
            String normalizedIp = normalizeIpAddress(ipAddress);
            String cacheKey = CACHE_PREFIX + normalizedIp;
            redisTemplate.delete(cacheKey);
            logger.info("Cache cleared for IP: {}", normalizedIp);
        }
    }

    // Method to get cache statistics (optional)
    public long getCacheSize() {
        try {
            Set<String> keys = redisTemplate.keys(CACHE_PREFIX + "*");
            return keys != null ? keys.size() : 0;
        } catch (Exception e) {
            logger.warn("Failed to get cache size", e);
            return -1;
        }
    }
}