package akin.city_card.redis;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import java.time.Duration;

@Configuration
@ConditionalOnProperty(
        name = "app.redis.enabled",
        havingValue = "true",
        matchIfMissing = false // false yapıldı: `app.redis.enabled` tanımsızsa Redis açılmaz
)
public class RedisConfig {

    @Bean
    public RedisCacheManager cacheManager(RedisConnectionFactory redisConnectionFactory) {
        return RedisCacheManager.builder(redisConnectionFactory)
                .cacheDefaults(
                        RedisCacheConfiguration.defaultCacheConfig()
                                .entryTtl(Duration.ofMinutes(10)) // Her key 10 dk cache'te kalır
                                .disableCachingNullValues()
                )
                .build();
    }
}
