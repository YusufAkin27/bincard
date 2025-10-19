package akin.city_card.news.repository;

import akin.city_card.news.model.News;
import akin.city_card.news.model.NewsViewHistory;
import akin.city_card.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface NewsViewHistoryRepository extends JpaRepository<NewsViewHistory, Long> {

    boolean existsByUserAndNews(User user, News news);

    List<NewsViewHistory> findByViewedAtAfter(LocalDateTime startOfMonth);

    boolean existsByUserIdAndNewsId(Long userId, Long newsId);
}
