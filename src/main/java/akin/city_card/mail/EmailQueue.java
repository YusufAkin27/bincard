package akin.city_card.mail;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class EmailQueue {

    private static final String EMAIL_QUEUE_KEY = "emailQueue";

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    public void enqueue(EmailMessage email) {
        try {
            String json = objectMapper.writeValueAsString(email);
            redisTemplate.opsForList().rightPush(EMAIL_QUEUE_KEY, json);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Email JSON serialize hatası", e);
        }
    }

    public String dequeue() {
        try {
            return redisTemplate.opsForList().leftPop(EMAIL_QUEUE_KEY);
        } catch (Exception e) {
            System.err.println("Redis'den dequeue sırasında hata: " + e.getMessage());
            return null;
        }
    }

    public boolean isEmpty() {
        Long size = redisTemplate.opsForList().size(EMAIL_QUEUE_KEY);
        return size == null || size == 0;
    }

    public long size() {
        Long size = redisTemplate.opsForList().size(EMAIL_QUEUE_KEY);
        return size == null ? 0 : size;
    }

    // Kuyruğu tamamen temizle
    public void clear() {
        try {
            redisTemplate.delete(EMAIL_QUEUE_KEY);
        } catch (Exception e) {
            System.err.println("Redis kuyruk temizlenirken hata: " + e.getMessage());
        }
    }
}


