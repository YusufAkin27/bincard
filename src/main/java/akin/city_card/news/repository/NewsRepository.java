package akin.city_card.news.repository;

import akin.city_card.news.model.News;
import akin.city_card.news.model.NewsType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface NewsRepository extends JpaRepository<News,Long> {
    List<News> findByTypeAndActiveTrue(NewsType type);

}
