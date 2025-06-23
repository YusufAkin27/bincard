package akin.city_card.news.repository;

import akin.city_card.news.model.NewsLike;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NewsLikeRepository extends JpaRepository<NewsLike, Integer> {
}
