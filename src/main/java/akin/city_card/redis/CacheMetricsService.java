package akin.city_card.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Properties;

// Cache metrics için servis
@Service
@RequiredArgsConstructor
public class CacheMetricsService {

    private final RedisTemplate<String, Object> redisTemplate;
    private long cacheHits = 0;
    private long cacheMisses = 0;
    private long totalRequests = 0;

    public void recordCacheHit() {
        cacheHits++;
        totalRequests++;
    }

    public void recordCacheMiss() {
        cacheMisses++;
        totalRequests++;
    }

    public double getCacheHitRatio() {
        return totalRequests > 0 ? (double) cacheHits / totalRequests * 100 : 0;
    }

    public CacheStats getCacheStats() {
        return new CacheStats(cacheHits, cacheMisses, totalRequests, getCacheHitRatio());
    }

    public void resetStats() {
        cacheHits = 0;
        cacheMisses = 0;
        totalRequests = 0;
    }

    // Redis server bilgileri
    public RedisInfo getRedisInfo() {
        try {
            RedisConnection connection = redisTemplate.getConnectionFactory().getConnection();
            Properties info = connection.info();
            connection.close();

            return new RedisInfo(
                    info.getProperty("used_memory_human", "N/A"),
                    info.getProperty("connected_clients", "N/A"),
                    info.getProperty("total_commands_processed", "N/A"),
                    info.getProperty("keyspace_hits", "N/A"),
                    info.getProperty("keyspace_misses", "N/A")
            );
        } catch (Exception e) {
            System.err.println("Redis info alınırken hata: " + e.getMessage());
            return new RedisInfo("N/A", "N/A", "N/A", "N/A", "N/A");
        }
    }

    public static class CacheStats {
        public final long hits;
        public final long misses;
        public final long totalRequests;
        public final double hitRatio;

        public CacheStats(long hits, long misses, long totalRequests, double hitRatio) {
            this.hits = hits;
            this.misses = misses;
            this.totalRequests = totalRequests;
            this.hitRatio = hitRatio;
        }

        @Override
        public String toString() {
            return String.format("CacheStats{hits=%d, misses=%d, total=%d, hitRatio=%.2f%%}",
                    hits, misses, totalRequests, hitRatio);
        }
    }

    public static class RedisInfo {
        public final String usedMemory;
        public final String connectedClients;
        public final String totalCommands;
        public final String keyspaceHits;
        public final String keyspaceMisses;

        public RedisInfo(String usedMemory, String connectedClients, String totalCommands,
                         String keyspaceHits, String keyspaceMisses) {
            this.usedMemory = usedMemory;
            this.connectedClients = connectedClients;
            this.totalCommands = totalCommands;
            this.keyspaceHits = keyspaceHits;
            this.keyspaceMisses = keyspaceMisses;
        }

        @Override
        public String toString() {
            return String.format("RedisInfo{memory=%s, clients=%s, commands=%s, hits=%s, misses=%s}",
                    usedMemory, connectedClients, totalCommands, keyspaceHits, keyspaceMisses);
        }
    }
}