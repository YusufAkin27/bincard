package akin.city_card.redis;

import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.core.converter.UserConverter;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class EnhancedCachedUserLookupService {

    private final UserRepository userRepository;
    private final UserConverter userConverter;
    private final CacheMetricsService metricsService;
    private final RedisTemplate<String, Object> redisTemplate;

    @Cacheable(value = "users", key = "#username", unless = "#result == null")
    public CacheUserDTO findByUsername(String username) throws UserNotFoundException {
        System.out.println("CACHE MISS - Veritabanından çağrılıyor: " + username);
        metricsService.recordCacheMiss();

        return userRepository.findByUserNumber(username)
                .map(userConverter::toCacheUserDTO)
                .orElseThrow(UserNotFoundException::new);
    }

    // Metrics ile cache hit/miss tracking
    public CacheUserDTO findByUsernameWithMetrics(String username) throws UserNotFoundException {
        // Cache'de var mı kontrol et
        if (redisTemplate.hasKey("users::" + username)) {
            metricsService.recordCacheHit();
            System.out.println("CACHE HIT - Cache'den alınıyor: " + username);
        }

        return findByUsername(username);
    }

    @CacheEvict(value = "users", key = "#username")
    public void evictCache(String username) {
        System.out.println("Cache temizlendi: " + username);
    }

    @CacheEvict(value = "users", allEntries = true)
    public void evictAllCache() {
        System.out.println("Tüm cache temizlendi");
    }

    // Bulk operations
    public void evictCacheBulk(List<String> usernames) {
        Instant start = Instant.now();
        for (String username : usernames) {
            evictCache(username);
        }
        Instant end = Instant.now();
        System.out.println("Bulk cache eviction - " + usernames.size() +
                " item: " + java.time.Duration.between(start, end).toMillis() + "ms");
    }

    // Cache preloading
    public void preloadCache(List<String> usernames) {
        System.out.println("Cache preloading başlıyor - " + usernames.size() + " kullanıcı");

        Instant start = Instant.now();
        for (String username : usernames) {
            try {
                findByUsername(username);
            } catch (Exception e) {
                System.err.println("Preload error for " + username + ": " + e.getMessage());
            }
        }
        Instant end = Instant.now();

        long duration = java.time.Duration.between(start, end).toMillis();
        System.out.println("Cache preloading tamamlandı: " + duration + "ms");
    }

    // Cache warm-up stratejisi
    public void warmUpCache(int batchSize, int delayMs) {
        System.out.println("Cache warm-up başlıyor - Batch size: " + batchSize + ", Delay: " + delayMs + "ms");

        List<User> allUsers = userRepository.findAll();
        int processed = 0;

        for (int i = 0; i < allUsers.size(); i += batchSize) {
            int endIndex = Math.min(i + batchSize, allUsers.size());
            List<User> batch = allUsers.subList(i, endIndex);

            for (User user : batch) {
                try {
                    findByUsername(user.getUserNumber());
                    processed++;
                } catch (Exception e) {
                    System.err.println("Warm-up error: " + e.getMessage());
                }
            }

            if (delayMs > 0) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            if (processed % 1000 == 0) {
                System.out.println("Warm-up progress: " + processed + "/" + allUsers.size());
            }
        }

        System.out.println("Cache warm-up tamamlandı: " + processed + " kullanıcı");
    }

    // Cache status kontrolü
    public CacheStatus getCacheStatus() {
        try {
            // Redis'ten cache bilgilerini al
            Long cacheSize = redisTemplate.getConnectionFactory().getConnection().dbSize();

            // Memory kullanımı
            CacheMetricsService.RedisInfo redisInfo = metricsService.getRedisInfo();

            return new CacheStatus(
                    cacheSize != null ? cacheSize : 0,
                    redisInfo.usedMemory,
                    metricsService.getCacheStats()
            );
        } catch (Exception e) {
            return new CacheStatus(0, "N/A", metricsService.getCacheStats());
        }
    }

    public static class CacheStatus {
        public final long totalKeys;
        public final String memoryUsage;
        public final CacheMetricsService.CacheStats stats;

        public CacheStatus(long totalKeys, String memoryUsage, CacheMetricsService.CacheStats stats) {
            this.totalKeys = totalKeys;
            this.memoryUsage = memoryUsage;
            this.stats = stats;
        }

        @Override
        public String toString() {
            return String.format("CacheStatus{totalKeys=%d, memory=%s, hitRatio=%.2f%%}",
                    totalKeys, memoryUsage, stats.hitRatio);
        }
    }

    // Test için özel metodlar
    public long timeDbRead(String username) {
        Instant start = Instant.now();
        userRepository.findByUserNumber(username);
        Instant end = Instant.now();
        return java.time.Duration.between(start, end).toNanos() / 1_000_000; // milliseconds
    }

    public long timeCacheRead(String username) {
        Instant start = Instant.now();
        try {
            findByUsername(username);
        } catch (Exception e) {
            // Handle exception
        }
        Instant end = Instant.now();
        return java.time.Duration.between(start, end).toNanos() / 1_000_000; // milliseconds
    }

    // Batch read performance
    public BatchReadResult batchReadFromDb(List<String> usernames) {
        Instant start = Instant.now();
        int successCount = 0;

        for (String username : usernames) {
            if (userRepository.findByUserNumber(username).isPresent()) {
                successCount++;
            }
        }

        Instant end = Instant.now();
        long duration = java.time.Duration.between(start, end).toMillis();

        return new BatchReadResult(successCount, usernames.size(), duration);
    }

    public BatchReadResult batchReadFromCache(List<String> usernames) {
        Instant start = Instant.now();
        int successCount = 0;

        for (String username : usernames) {
            try {
                findByUsername(username);
                successCount++;
            } catch (Exception e) {
                // Exception durumunda devam et
            }
        }

        Instant end = Instant.now();
        long duration = java.time.Duration.between(start, end).toMillis();

        return new BatchReadResult(successCount, usernames.size(), duration);
    }

    public static class BatchReadResult {
        public final int successCount;
        public final int totalCount;
        public final long durationMs;
        public final double successRate;
        public final double throughput; // operations per second

        public BatchReadResult(int successCount, int totalCount, long durationMs) {
            this.successCount = successCount;
            this.totalCount = totalCount;
            this.durationMs = durationMs;
            this.successRate = totalCount > 0 ? (double) successCount / totalCount * 100 : 0;
            this.throughput = durationMs > 0 ? (double) totalCount / (durationMs / 1000.0) : 0;
        }

        @Override
        public String toString() {
            return String.format("BatchReadResult{success=%d/%d (%.1f%%), duration=%dms, throughput=%.1f ops/sec}",
                    successCount, totalCount, successRate, durationMs, throughput);
        }
    }
}