package akin.city_card.news.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.NewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.exceptions.NewsIsNotActiveException;
import akin.city_card.news.exceptions.NewsNotFoundException;
import akin.city_card.news.exceptions.OutDatedNewsException;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import jakarta.validation.Valid;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ExecutionException;

public interface NewsService {
    List<NewsDTO> getAllForAdmin(String username, PlatformType platform) throws AdminNotFoundException;


    ResponseMessage createNews(String username, @Valid CreateNewsRequest news) throws AdminNotFoundException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException;

    ResponseMessage softDeleteNews(String username, Long id) throws NewsNotFoundException, AdminNotFoundException;

    ResponseMessage updateNews(String username, UpdateNewsRequest updatedNews) throws AdminNotFoundException, NewsNotFoundException, NewsIsNotActiveException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException;

    NewsDTO getNewsByIdForAdmin(String username, Long id) throws NewsIsNotActiveException, NewsNotFoundException, AdminNotFoundException;

    NewsDTO getNewsByIdForUser(String username, Long id) throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException;


    List<NewsDTO> getNewsBetweenDates(String username, LocalDateTime start, LocalDateTime end, PlatformType platform) throws AdminNotFoundException;

    List<NewsDTO> getLikedNewsByUser(String username) throws UserNotFoundException;

    ResponseMessage likeNews(Long newsId, String username) throws OutDatedNewsException, NewsIsNotActiveException, NewsNotFoundException, UserNotFoundException;

    ResponseMessage unlikeNews(Long newsId, String username) throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException, OutDatedNewsException;

    List<NewsDTO> getPersonalizedNews(String username, PlatformType platform) throws UserNotFoundException;

    List<NewsStatistics> getMonthlyNewsStatistics(String username) throws AdminNotFoundException;

    List<NewsDTO> getNewsByCategoryForAdmin(String username, NewsType category, PlatformType platform);

    List<NewsDTO> getNewsByCategoryForUser(String username, NewsType category, PlatformType platform) throws UserNotFoundException;

    List<NewsHistoryDTO> getNewsViewHistory(String username) throws UserNotFoundException;

    void recordNewsView(String username, Long newsId) throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException;

    List<NewsDTO> getSuggestedNews(String username, PlatformType platformType) throws UserNotFoundException;

    List<NewsDTO> getActiveNewsForUser(PlatformType platform, NewsType type, String username) throws UserNotFoundException;

    NewsDTO getActiveNewsForAdmin(PlatformType platform, NewsType type, String username) throws AdminNotFoundException;
}
