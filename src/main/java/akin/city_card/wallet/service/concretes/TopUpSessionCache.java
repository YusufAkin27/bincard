package akin.city_card.wallet.service.concretes;

import akin.city_card.wallet.core.response.TopUpSessionData;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TopUpSessionCache {

    private final Map<String, TopUpSessionData> sessionMap = new ConcurrentHashMap<>();

    public void put(String conversationId, TopUpSessionData data) {
        sessionMap.put(conversationId, data);
    }

    public TopUpSessionData get(String conversationId) {
        return sessionMap.get(conversationId);
    }

    public void remove(String conversationId) {
        sessionMap.remove(conversationId);
    }
}
