package akin.city_card.news.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.NewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.exceptions.*;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.news.service.abstracts.NewsService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.core.response.Views;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import com.fasterxml.jackson.annotation.JsonView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ExecutionException;

@RestController
@RequestMapping("/v1/api/news")
@RequiredArgsConstructor
public class NewsController {

    private final NewsService newsService;

    @GetMapping("/")
    @JsonView(Views.Admin.class)
    public List<NewsDTO> getAll(@AuthenticationPrincipal UserDetails userDetails,
                                @RequestParam(name = "platform", required = false) PlatformType platform)
            throws AdminNotFoundException, UnauthorizedAreaException {
        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();

        return newsService.getAllForAdmin(userDetails.getUsername(), platform);
    }

    @PostMapping(value = "/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseMessage createNews(@AuthenticationPrincipal UserDetails userDetails,
                                      @Valid @ModelAttribute CreateNewsRequest news)
            throws AdminNotFoundException, UnauthorizedAreaException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException {

        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();
        return newsService.createNews(userDetails.getUsername(), news);
    }

    @PutMapping("/{id}/soft-delete")
    public ResponseMessage softDeleteNews(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id)
            throws NewsNotFoundException, AdminNotFoundException, UnauthorizedAreaException {

        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();
        return newsService.softDeleteNews(userDetails.getUsername(), id);
    }

    @PutMapping(value = "/update", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseMessage updateNews(@AuthenticationPrincipal UserDetails userDetails,
                                      @Valid @ModelAttribute UpdateNewsRequest request)
            throws NewsNotFoundException, AdminNotFoundException, UnauthorizedAreaException, NewsIsNotActiveException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException {

        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();

        return newsService.updateNews(userDetails.getUsername(), request);
    }

    @GetMapping("/admin/{id}")
    @JsonView(Views.Admin.class)
    public NewsDTO getNewsByIdForAdmin(@AuthenticationPrincipal UserDetails userDetails,
                                       @PathVariable Long id)
            throws AdminNotFoundException, NewsNotFoundException, NewsIsNotActiveException, UnauthorizedAreaException {
        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();
        return newsService.getNewsByIdForAdmin(userDetails.getUsername(), id);
    }

    // Anonim kullanıcılar da erişebilir
    @GetMapping("/{id}")
    @JsonView(Views.User.class)
    public NewsDTO getNewsByIdForUser(@AuthenticationPrincipal UserDetails userDetails,
                                      @PathVariable Long id,
                                      HttpServletRequest request)
            throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException {

        String username = userDetails != null ? userDetails.getUsername() : null;
        String clientIp = getClientIpAddress(request);
        String sessionId = request.getSession().getId();
        String userAgent = request.getHeader("User-Agent"); // ✅ User-Agent bilgisi

        return newsService.getNewsByIdForUser(username, id, clientIp, sessionId, userAgent);
    }


    // Anonim kullanıcılar da erişebilir
    @GetMapping("/active")
    @JsonView(Views.User.class)
    public List<NewsDTO> getActiveNewsForUser(@AuthenticationPrincipal UserDetails userDetails,
                                              @RequestParam(required = false) PlatformType platform,
                                              @RequestParam(required = false) NewsType type,
                                              HttpServletRequest request)
            throws UserNotFoundException, AdminNotFoundException {
        String username = userDetails != null ? userDetails.getUsername() : null;
        String clientIp = getClientIpAddress(request);
        return newsService.getActiveNewsForUser(platform, type, username, clientIp);
    }

    @GetMapping("/active-admin")
    @JsonView(Views.Admin.class)
    public NewsDTO getActiveNewsForAdmin(@AuthenticationPrincipal UserDetails userDetails,
                                         @RequestParam(required = false) PlatformType platform,
                                         @RequestParam(required = false) NewsType type)
            throws AdminNotFoundException, UnauthorizedAreaException {
        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();
        return newsService.getActiveNewsForAdmin(platform, type, userDetails.getUsername());
    }

    @GetMapping("/between-dates")
    @JsonView(Views.Admin.class)
    public List<NewsDTO> getNewsBetweenDates(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end,
            @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws AdminNotFoundException, UnauthorizedAreaException {

        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();

        if (end == null) {
            end = LocalDateTime.now();
        }

        return newsService.getNewsBetweenDates(userDetails.getUsername(), start, end, platform);
    }

    // Giriş yapmış kullanıcılar için
    @GetMapping("/liked")
    @JsonView(Views.User.class)
    public List<NewsDTO> getLikedNewsByUser(@AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException, UnauthorizedAreaException {
        if (userDetails == null) throw new UnauthorizedAreaException();
        return newsService.getLikedNewsByUser(userDetails.getUsername());
    }

    // Giriş yapmış kullanıcılar için
    @PostMapping("/{newsId}/like")
    public ResponseMessage likeNews(@PathVariable Long newsId,
                                    @AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException, OutDatedNewsException, NewsAlreadyLikedException, UnauthorizedAreaException {
        if (userDetails == null) throw new UnauthorizedAreaException();
        return newsService.likeNews(newsId, userDetails.getUsername());
    }

    // Giriş yapmış kullanıcılar için
    @DeleteMapping("/{newsId}/unlike")
    public ResponseMessage unlikeNews(@PathVariable Long newsId,
                                      @AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException, OutDatedNewsException, NewsNotLikedException, UnauthorizedAreaException {
        if (userDetails == null) throw new UnauthorizedAreaException();
        return newsService.unlikeNews(newsId, userDetails.getUsername());
    }

    // Giriş yapmış kullanıcılar için
    @GetMapping("/personalized")
    @JsonView(Views.User.class)
    public List<NewsDTO> getPersonalizedNews(@AuthenticationPrincipal UserDetails userDetails,
                                             @RequestParam(name = "platform", required = false) PlatformType platform)
            throws UserNotFoundException, UnauthorizedAreaException {
        if (userDetails == null) throw new UnauthorizedAreaException();
        return newsService.getPersonalizedNews(userDetails.getUsername(), platform);
    }

    @GetMapping("/statistics")
    public List<NewsStatistics> getMonthlyNewsStatistics(@AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, UnauthorizedAreaException {
        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();
        return newsService.getMonthlyNewsStatistics(userDetails.getUsername());
    }

    @GetMapping("/admin/by-category")
    @JsonView(Views.Admin.class)
    public List<NewsDTO> getNewsByCategoryForAdmin(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(name = "category") NewsType category,
            @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws AdminNotFoundException, UnauthorizedAreaException {
        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();
        return newsService.getNewsByCategoryForAdmin(userDetails.getUsername(), category, platform);
    }

    // Anonim kullanıcılar da erişebilir
    @GetMapping("/by-category")
    @JsonView(Views.User.class)
    public List<NewsDTO> getNewsByCategoryForUser(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(name = "category") NewsType category,
            @RequestParam(name = "platform", required = false) PlatformType platform,
            HttpServletRequest request
    ) throws UserNotFoundException {
        String username = userDetails != null ? userDetails.getUsername() : null;
        String clientIp = getClientIpAddress(request);
        return newsService.getNewsByCategoryForUser(username, category, platform, clientIp);
    }

    // Giriş yapmış kullanıcılar için
    @GetMapping("/view-history")
    public List<NewsHistoryDTO> getNewsViewHistory(@AuthenticationPrincipal UserDetails userDetails,
                                                   @RequestParam(name = "platform", required = false) PlatformType platform)
            throws UserNotFoundException, UnauthorizedAreaException {
        if (userDetails == null) throw new UnauthorizedAreaException();
        return newsService.getNewsViewHistory(userDetails.getUsername());
    }

    // Anonim kullanıcılar da erişebilir
    @GetMapping("/suggested")
    @JsonView(Views.User.class)
    public List<NewsDTO> getSuggestedNews(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(name = "platform", required = false) PlatformType platform,
            HttpServletRequest request
    ) throws UserNotFoundException {
        String username = userDetails != null ? userDetails.getUsername() : null;
        String clientIp = getClientIpAddress(request);
        return newsService.getSuggestedNews(username, platform, clientIp);
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}