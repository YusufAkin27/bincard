package akin.city_card.news.service.concretes;

import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.AdminNewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.core.response.UserNewsDTO;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.news.repository.NewsLikeRepository;
import akin.city_card.news.repository.NewsRepository;
import akin.city_card.news.repository.NewsViewHistoryRepository;
import akin.city_card.news.service.abstracts.NewsService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class NewsManager implements NewsService {
    private final NewsRepository newsRepository;
    private final NewsLikeRepository newsLikeRepository;
    private final NewsViewHistoryRepository newsViewHistoryRepository;


    @Override
    public DataResponseMessage<?> getAllForAdmin(String username) {
        return null;
    }

    @Override
    public DataResponseMessage<?> getAllForUser(String username) {
        return null;
    }

    @Override
    public ResponseMessage createNews(String username, CreateNewsRequest news) {
        return null;
    }

    @Override
    public ResponseMessage softDeleteNews(String username, Long id) {
        return null;
    }

    @Override
    public ResponseMessage updateNews(String username, UpdateNewsRequest updatedNews) {
        return null;
    }

    @Override
    public DataResponseMessage<?> getNewsByIdForAdmin(String username, Long id) {
        return null;
    }

    @Override
    public DataResponseMessage<?> getNewsByIdForUser(String username, Long id) {
        return null;
    }

    @Override
    public DataResponseMessage<?> getActiveNewsForAdmin(PlatformType platform, NewsType type, String username) {
        return null;
    }

    @Override
    public DataResponseMessage<?> getActiveNewsForUser(PlatformType platform, NewsType type, String username) {
        return null;
    }

    @Override
    public ResponseMessage activateNews(String username, Long id) {
        return null;
    }

    @Override
    public DataResponseMessage<List<AdminNewsDTO>> getNewsBetweenDates(String username, LocalDateTime start, LocalDateTime end) {
        return null;
    }

    @Override
    public DataResponseMessage<List<UserNewsDTO>> getLikedNewsByUser(String username) {
        return null;
    }

    @Override
    public ResponseMessage likeNews(Long newsId, String username) {
        return null;
    }

    @Override
    public ResponseMessage unlikeNews(Long newsId, String username) {
        return null;
    }

    @Override
    public DataResponseMessage<List<UserNewsDTO>> getPersonalizedNews(String username) {
        return null;
    }

    @Override
    public DataResponseMessage<List<NewsStatistics>> getTopNewsStatistics(String username) {
        return null;
    }

    @Override
    public DataResponseMessage<List<?>> getNewsByCategoryForAdmin(String username, NewsType category) {
        return null;
    }

    @Override
    public DataResponseMessage<List<?>> getNewsByCategoryForUser(String username, NewsType category) {
        return null;
    }

    @Override
    public DataResponseMessage<List<NewsHistoryDTO>> getNewsViewHistory(String username) {
        return null;
    }

    @Override
    public void recordNewsView(String username, Long newsId) {

    }

    @Override
    public DataResponseMessage<List<UserNewsDTO>> getSuggestedNews(String username) {
        return null;
    }
}
