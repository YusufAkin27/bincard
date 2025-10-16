package akin.city_card.news.repository;

import akin.city_card.news.model.AnonymousNewsViewHistory;
import akin.city_card.news.model.News;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AnonymousNewsViewHistoryRepository extends JpaRepository<AnonymousNewsViewHistory, Long> {

    List<AnonymousNewsViewHistory> findTop10ByClientIpOrderByViewedAtDesc(String clientIp);

    long countByNews(News news);

    boolean existsBySessionIdAndNewsId(String sessionId, Long newsId);

    boolean existsByClientIpAndNews(String clientIp, News news);

    boolean existsByNewsIdAndClientIpAndSessionIdAndUserAgent(Long newsId, String clientIp, String sessionId, String userAgent);
}
