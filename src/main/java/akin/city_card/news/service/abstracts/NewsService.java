package akin.city_card.news.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.NewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.exceptions.*;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ExecutionException;

public interface NewsService {

    // Admin işlemleri
    List<NewsDTO> getAllForAdmin(String username, PlatformType platform) throws AdminNotFoundException;

    ResponseMessage createNews(String username, CreateNewsRequest createNewsRequest)
            throws AdminNotFoundException, PhotoSizeLargerException, IOException, ExecutionException,
            InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException,
            FileFormatCouldNotException;

    ResponseMessage softDeleteNews(String username, Long id)
            throws NewsNotFoundException, AdminNotFoundException;

    ResponseMessage updateNews(String username, UpdateNewsRequest updatedNews)
            throws AdminNotFoundException, NewsNotFoundException, NewsIsNotActiveException,
            PhotoSizeLargerException, IOException, ExecutionException, InterruptedException,
            OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException;

    NewsDTO getNewsByIdForAdmin(String username, Long id)
            throws NewsIsNotActiveException, NewsNotFoundException, AdminNotFoundException;

    NewsDTO getActiveNewsForAdmin(PlatformType platform, NewsType type, String username)
            throws AdminNotFoundException;

    List<NewsDTO> getNewsBetweenDates(String username, LocalDateTime start, LocalDateTime end, PlatformType platform)
            throws AdminNotFoundException;

    List<NewsStatistics> getMonthlyNewsStatistics(String username) throws AdminNotFoundException;

    List<NewsDTO> getNewsByCategoryForAdmin(String username, NewsType category, PlatformType platform);

    // Kullanıcı işlemleri (giriş yapmış)
    List<NewsDTO> getLikedNewsByUser(String username) throws UserNotFoundException;

    ResponseMessage likeNews(Long newsId, String username)
            throws OutDatedNewsException, NewsIsNotActiveException, NewsNotFoundException,
            UserNotFoundException, NewsAlreadyLikedException;

    ResponseMessage unlikeNews(Long newsId, String username)
            throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException,
            OutDatedNewsException, NewsNotLikedException;

    List<NewsDTO> getPersonalizedNews(String username, PlatformType platform) throws UserNotFoundException;

    List<NewsHistoryDTO> getNewsViewHistory(String username,PlatformType platformType) throws UserNotFoundException;

    // Hem giriş yapmış hem anonim kullanıcılar için
    NewsDTO getNewsByIdForUser(String username, PlatformType type,Long id, String clientIp,String sessionId,String userAgent)
            throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException;

    List<NewsDTO> getActiveNewsForUser(PlatformType platform, NewsType type, String username, String clientIp)
            throws UserNotFoundException, AdminNotFoundException;

    List<NewsDTO> getNewsByCategoryForUser(String username, NewsType category, PlatformType platform, String clientIp)
            throws UserNotFoundException;

    List<NewsDTO> getSuggestedNews(String username, PlatformType platformType, String clientIp)
            throws UserNotFoundException;

    // İç işlemler
    void recordNewsView(String username, Long newsId)
            throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException;

    void recordAnonymousNewsView(String clientIp, Long newsId, String userAgent, String sessionId)
            throws NewsIsNotActiveException, NewsNotFoundException;

    // Scheduler için
    void activateScheduledNews();
    void deactivateExpiredNews();
    void performDailyStatusCheck();
}