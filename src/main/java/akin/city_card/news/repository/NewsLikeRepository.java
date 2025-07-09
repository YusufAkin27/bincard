package akin.city_card.news.repository;

import akin.city_card.news.model.NewsLike;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface NewsLikeRepository extends JpaRepository<NewsLike, Integer> {
    List<NewsLike> findByLikedAtAfter(LocalDateTime startOfMonth);

    boolean existsByUserIdAndNewsId(Long userId, Long newsId);
}
