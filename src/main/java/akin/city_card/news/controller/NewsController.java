package akin.city_card.news.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.core.request.*;
import akin.city_card.news.core.response.AdminNewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.core.response.UserNewsDTO;
import akin.city_card.news.exceptions.*;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.news.service.abstracts.NewsService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.Role;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
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
    public DataResponseMessage<List<AdminNewsDTO>> getAll(@AuthenticationPrincipal UserDetails userDetails,
                                                          @RequestParam(name = "platform", required = false) PlatformType platform
    )
            throws AdminNotFoundException, UnauthorizedAreaException {
        if (userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();

        return newsService.getAllForAdmin(userDetails.getUsername(), platform);
    }


    @PostMapping(value = "/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseMessage createNews(@AuthenticationPrincipal UserDetails userDetails,
                                      @Valid @ModelAttribute CreateNewsRequest news)
            throws AdminNotFoundException, UnauthorizedAreaException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException {

        if (userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();
        return newsService.createNews(userDetails.getUsername(), news);
    }


    @PutMapping("/{id}/soft-delete")
    public ResponseMessage softDeleteNews(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id) throws NewsNotFoundException, AdminNotFoundException, UnauthorizedAreaException {

        if (userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();
        return newsService.softDeleteNews(userDetails.getUsername(), id);
    }

    @PutMapping(value = "/update", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseMessage updateNews(@AuthenticationPrincipal UserDetails userDetails,
                                      @Valid @ModelAttribute UpdateNewsRequest request)
            throws NewsNotFoundException, AdminNotFoundException, UnauthorizedAreaException, NewsIsNotActiveException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException {

        if (userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();

        return newsService.updateNews(userDetails.getUsername(), request);
    }

    @GetMapping("/{id}")
    public DataResponseMessage<?> getNewsById(@AuthenticationPrincipal UserDetails userDetails,
                                              @PathVariable Long id) throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException, AdminNotFoundException {

        boolean isAdmin = userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ADMIN"));

        if (isAdmin) {
            return newsService.getNewsByIdForAdmin(userDetails.getUsername(), id); // AdminNewsDTO
        } else {
            return newsService.getNewsByIdForUser(userDetails.getUsername(), id); // UserNewsDTO
        }
    }


    @GetMapping("/active")
    public DataResponseMessage<?> getActiveNews(@AuthenticationPrincipal UserDetails userDetails,
                                                @RequestParam(required = false) PlatformType platform,
                                                @RequestParam(required = false) NewsType type) throws UserNotFoundException, AdminNotFoundException {

        boolean isAdmin = userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals(Role.ADMIN.getAuthority()));

        if (isAdmin) {
            return newsService.getActiveNewsForAdmin(platform, type, userDetails.getUsername()); // List<AdminNewsDTO>
        } else {
            return newsService.getActiveNewsForUser(platform, type, userDetails.getUsername()); // List<UserNewsDTO>
        }
    }




    @GetMapping("/between-dates")
    public DataResponseMessage<List<AdminNewsDTO>> getNewsBetweenDates(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end,
            @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws AdminNotFoundException, UnauthorizedAreaException {

        if (userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();

        if (end == null) {
            end = LocalDateTime.now();
        }

        return newsService.getNewsBetweenDates(userDetails.getUsername(), start, end, platform);
    }

    @GetMapping("/liked")
    public DataResponseMessage<List<UserNewsDTO>> getLikedNewsByUser(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return newsService.getLikedNewsByUser(userDetails.getUsername());
    }

    @PostMapping("/{newsId}/like")
    public ResponseMessage likeNews(@PathVariable Long newsId, @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException, OutDatedNewsException {
        return newsService.likeNews(newsId, userDetails.getUsername());
    }

    @DeleteMapping("/{newsId}/unlike")
    public ResponseMessage unlikeNews(@PathVariable Long newsId, @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException, OutDatedNewsException {
        return newsService.unlikeNews(newsId, userDetails.getUsername());
    }

    @GetMapping("/personalized")
    public DataResponseMessage<List<UserNewsDTO>> getPersonalizedNews(@AuthenticationPrincipal UserDetails userDetails, @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws UserNotFoundException {
        return newsService.getPersonalizedNews(userDetails.getUsername(), platform);
    }


    @GetMapping("/statistics")
    public DataResponseMessage<List<NewsStatistics>> getMonthlyNewsStatistics(@AuthenticationPrincipal UserDetails userDetails) throws AdminNotFoundException, UnauthorizedAreaException {

        if (userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();
        return newsService.getMonthlyNewsStatistics(userDetails.getUsername());
    }

    // Kategoriye göre haber listeleme
    @GetMapping("/by-category")
    public DataResponseMessage<List<?>> getNewsByCategory(@AuthenticationPrincipal UserDetails userDetails, @RequestParam NewsType category,
                                                          @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws UserNotFoundException {
        boolean isAdmin = userDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ADMIN"));
        if (isAdmin) {
            return newsService.getNewsByCategoryForAdmin(userDetails.getUsername(), category, platform);
        }
        return newsService.getNewsByCategoryForUser(userDetails.getUsername(), category, platform);

    }

    // Kullanıcı haber geçmişi (kim ne zaman neyi okudu)
    @GetMapping("/view-history")
    public DataResponseMessage<List<NewsHistoryDTO>> getNewsViewHistory(@AuthenticationPrincipal UserDetails userDetails, @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws UserNotFoundException {
        return newsService.getNewsViewHistory(userDetails.getUsername());
    }

    // Haber görüntülendiğinde otomatik olarak history kaydı yapılması (genellikle frontend'de tetiklenir)
    @PostMapping("/{newsId}/view")
    public void viewNews(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long newsId) throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException {
        newsService.recordNewsView(userDetails.getUsername(), newsId);
    }

    // Önerilen haberler (kategorilere göre kullanıcıya özel)
    @GetMapping("/suggested")
    public DataResponseMessage<List<UserNewsDTO>> getSuggestedNews(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws UserNotFoundException {
        return newsService.getSuggestedNews(userDetails.getUsername(), platform);
    }

}


