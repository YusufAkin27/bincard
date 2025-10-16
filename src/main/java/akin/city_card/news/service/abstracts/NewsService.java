package akin.city_card.news.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.AdminNewsDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.core.response.UserNewsDTO;
import akin.city_card.news.exceptions.*;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.concurrent.ExecutionException;

public interface NewsService {

    // Admin işlemleri

    ResponseMessage createNews(String username, CreateNewsRequest createNewsRequest)
            throws AdminNotFoundException, PhotoSizeLargerException, IOException, ExecutionException,
            InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException,
            FileFormatCouldNotException;

    void recordAnonymousNewsView(String clientIp, Long newsId, String userAgent, String sessionId) throws NewsIsNotActiveException, NewsNotFoundException;

    ResponseMessage softDeleteNews(String username, Long id)
            throws NewsNotFoundException, AdminNotFoundException;

    ResponseMessage updateNews(String username, UpdateNewsRequest updatedNews)
            throws AdminNotFoundException, NewsNotFoundException, NewsIsNotActiveException,
            PhotoSizeLargerException, IOException, ExecutionException, InterruptedException,
            OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException;

    AdminNewsDTO getNewsByIdForAdmin(String username, Long id)
            throws NewsIsNotActiveException, NewsNotFoundException, AdminNotFoundException;


    ResponseMessage likeNews(Long newsId, String username)
            throws OutDatedNewsException, NewsIsNotActiveException, NewsNotFoundException,
            UserNotFoundException, NewsAlreadyLikedException;

    ResponseMessage unlikeNews(Long newsId, String username)
            throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException,
            OutDatedNewsException, NewsNotLikedException;


    UserNewsDTO getNewsByIdForUser(String username, PlatformType type, Long id, String clientIp, String sessionId, String userAgent)
            throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException;


    void recordNewsView(String username, Long newsId)
            throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException;


    Page<AdminNewsDTO> getAllForAdmin(String username, PlatformType platform, Pageable pageable) throws AdminNotFoundException;

    PageDTO<UserNewsDTO> getActiveNewsForUser(PlatformType platform, NewsType type, String username, String clientIp, Pageable pageable) throws UserNotFoundException;

    PageDTO<AdminNewsDTO> getActiveNewsForAdmin(PlatformType platform, NewsType type, String username, Pageable pageable) throws AdminNotFoundException;

    PageDTO<UserNewsDTO> getNewsBetweenDates(String username, LocalDateTime localDateTime, LocalDateTime localDateTime1, PlatformType platform, Pageable pageable);

    PageDTO<UserNewsDTO> getLikedNewsByUser(String username, Pageable pageable) throws UserNotFoundException;


    PageDTO<NewsStatistics> getMonthlyNewsStatistics(String username, Pageable pageable) throws AdminNotFoundException;

    PageDTO<UserNewsDTO> getNewsByCategoryForAdmin(String username, NewsType category, PlatformType platform, Pageable pageable);

    PageDTO<UserNewsDTO> getNewsByCategoryForUser(String username, NewsType category, PlatformType platform, String clientIp, Pageable pageable) throws UserNotFoundException;


}