package akin.city_card.news.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.AdminNewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.core.response.UserNewsDTO;
import akin.city_card.news.exceptions.NewsIsAlreadyActiveException;
import akin.city_card.news.exceptions.NewsIsNotActiveException;
import akin.city_card.news.exceptions.NewsNotFoundException;
import akin.city_card.news.exceptions.OutDatedNewsException;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import jakarta.validation.Valid;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ExecutionException;

public interface NewsService {
    DataResponseMessage<List<AdminNewsDTO>> getAllForAdmin(String username) throws AdminNotFoundException;


    ResponseMessage createNews(String username, @Valid CreateNewsRequest news) throws AdminNotFoundException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException;

    ResponseMessage softDeleteNews(String username, Long id) throws NewsNotFoundException, AdminNotFoundException;

    ResponseMessage updateNews(String username, UpdateNewsRequest updatedNews) throws AdminNotFoundException, NewsNotFoundException, NewsIsNotActiveException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException;

    DataResponseMessage<?> getNewsByIdForAdmin(String username, Long id) throws NewsIsNotActiveException, NewsNotFoundException, AdminNotFoundException;

    DataResponseMessage<?> getNewsByIdForUser(String username, Long id) throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException;

    DataResponseMessage<?> getActiveNewsForAdmin(PlatformType platform, NewsType type, String username) throws AdminNotFoundException;

    DataResponseMessage<?> getActiveNewsForUser(PlatformType platform, NewsType type, String username) throws UserNotFoundException;

    ResponseMessage activateNews(String username, Long id) throws AdminNotFoundException, NewsNotFoundException, NewsIsAlreadyActiveException;

    DataResponseMessage<List<AdminNewsDTO>> getNewsBetweenDates(String username, LocalDateTime start, LocalDateTime end) throws AdminNotFoundException;

    DataResponseMessage<List<UserNewsDTO>> getLikedNewsByUser(String username) throws UserNotFoundException;

    ResponseMessage likeNews(Long newsId, String username) throws OutDatedNewsException, NewsIsNotActiveException, NewsNotFoundException, UserNotFoundException;

    ResponseMessage unlikeNews(Long newsId, String username) throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException, OutDatedNewsException;

    DataResponseMessage<List<UserNewsDTO>> getPersonalizedNews(String username) throws UserNotFoundException;

    DataResponseMessage<List<NewsStatistics>> getMonthlyNewsStatistics(String username) throws AdminNotFoundException;

    DataResponseMessage<List<?>> getNewsByCategoryForAdmin(String username, NewsType category);

    DataResponseMessage<List<?>> getNewsByCategoryForUser(String username, NewsType category) throws UserNotFoundException;

    DataResponseMessage<List<NewsHistoryDTO>> getNewsViewHistory(String username) throws UserNotFoundException;

    void recordNewsView(String username, Long newsId) throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException;

    DataResponseMessage<List<UserNewsDTO>> getSuggestedNews(String username,PlatformType platformType) throws UserNotFoundException;
}
