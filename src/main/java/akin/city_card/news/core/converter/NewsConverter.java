package akin.city_card.news.core.converter;

import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.AdminNewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.core.response.UserNewsDTO;
import akin.city_card.news.model.News;
import akin.city_card.news.model.NewsLike;
import akin.city_card.news.model.NewsViewHistory;

import java.util.List;

public interface NewsConverter {
    UserNewsDTO toNewsDTO(News news, boolean isLiked, boolean isViewed);

    NewsHistoryDTO toHistoryDTO(NewsViewHistory history);

    NewsStatistics toDetailedStatistics(News news, List<NewsLike> newsLikes, List<NewsViewHistory> newsViewHistories);

    News fromCreateRequest(CreateNewsRequest request);

    void updateEntityFromDTO(News news, UpdateNewsRequest dto);

    AdminNewsDTO toAdminNewsDTO(News news);


}
