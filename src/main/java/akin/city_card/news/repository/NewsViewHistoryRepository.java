package akin.city_card.news.repository;

import akin.city_card.news.model.NewsViewHistory;
import akin.city_card.user.model.User;
import akin.city_card.news.model.News;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;

public interface NewsViewHistoryRepository extends JpaRepository<NewsViewHistory, Long> {

}
