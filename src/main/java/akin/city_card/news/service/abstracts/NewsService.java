package akin.city_card.news.service.abstracts;

import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.AdminNewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.core.response.UserNewsDTO;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import jakarta.validation.Valid;

import java.time.LocalDateTime;
import java.util.List;

public interface NewsService {
    DataResponseMessage<?> getAllForAdmin(String username);

    DataResponseMessage<?> getAllForUser(String username);

    ResponseMessage createNews(String username, @Valid CreateNewsRequest news);

    ResponseMessage softDeleteNews(String username, Long id);

    ResponseMessage updateNews(String username, UpdateNewsRequest updatedNews);

    DataResponseMessage<?> getNewsByIdForAdmin(String username, Long id);

    DataResponseMessage<?> getNewsByIdForUser(String username, Long id);

    DataResponseMessage<?> getActiveNewsForAdmin(PlatformType platform, NewsType type, String username);

    DataResponseMessage<?> getActiveNewsForUser(PlatformType platform, NewsType type, String username);

    ResponseMessage activateNews(String username, Long id);

    DataResponseMessage<List<AdminNewsDTO>> getNewsBetweenDates(String username, LocalDateTime start, LocalDateTime end);

    DataResponseMessage<List<UserNewsDTO>> getLikedNewsByUser(String username);

    ResponseMessage likeNews(Long newsId, String username);

    ResponseMessage unlikeNews(Long newsId, String username);

    DataResponseMessage<List<UserNewsDTO>> getPersonalizedNews(String username);

    DataResponseMessage<List<NewsStatistics>> getTopNewsStatistics(String username);

    DataResponseMessage<List<?>> getNewsByCategoryForAdmin(String username, NewsType category);

    DataResponseMessage<List<?>> getNewsByCategoryForUser(String username, NewsType category);

    DataResponseMessage<List<NewsHistoryDTO>> getNewsViewHistory(String username);

    void recordNewsView(String username, Long newsId);

    DataResponseMessage<List<UserNewsDTO>> getSuggestedNews(String username);
}
