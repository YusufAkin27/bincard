package akin.city_card.news.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.NewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.exceptions.NewsIsNotActiveException;
import akin.city_card.news.exceptions.NewsNotFoundException;
import akin.city_card.news.exceptions.OutDatedNewsException;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
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
    @JsonView(Views.Admin.class) // Admin görünümleri
    public List<NewsDTO> getAll(@AuthenticationPrincipal UserDetails userDetails,
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

    @GetMapping("/admin/{id}")
    @JsonView(Views.Admin.class) // Admin görünümleri
    public NewsDTO getNewsByIdForAdmin(@AuthenticationPrincipal UserDetails userDetails,
                                                      @PathVariable Long id) throws AdminNotFoundException, NewsNotFoundException, NewsIsNotActiveException {
        // Burada admin kontrolü güvenlik katmanında yapılabilir, isteğe bağlı olarak buraya eklenebilir
        return newsService.getNewsByIdForAdmin(userDetails.getUsername(), id);
    }

    @GetMapping("/{id}")
    @JsonView(Views.User.class) // Admin görünümleri
    public NewsDTO getNewsByIdForUser(@AuthenticationPrincipal UserDetails userDetails,
                                                     @PathVariable Long id) throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException {
        return newsService.getNewsByIdForUser(userDetails.getUsername(), id);
    }



    @GetMapping("/active")
    @JsonView(Views.User.class) // Admin görünümleri
    public List<NewsDTO> getActiveNewsForUser(@AuthenticationPrincipal UserDetails userDetails,
                                                       @RequestParam(required = false) PlatformType platform,
                                                       @RequestParam(required = false) NewsType type) throws UserNotFoundException, AdminNotFoundException {

        return newsService.getActiveNewsForUser(platform, type, userDetails.getUsername()); // List<UserNewsDTO>
    }

    @GetMapping("/active-admin")
    @JsonView(Views.Admin.class) // Admin görünümleri
    public NewsDTO getActiveNewsForAdmin(@AuthenticationPrincipal UserDetails userDetails,
                                                        @RequestParam(required = false) PlatformType platform,
                                                        @RequestParam(required = false) NewsType type) throws AdminNotFoundException {

        return newsService.getActiveNewsForAdmin(platform, type, userDetails.getUsername()); // List<AdminNewsDTO>

    }


    @GetMapping("/between-dates")
    @JsonView(Views.Admin.class) // Admin görünümleri
    public List<NewsDTO> getNewsBetweenDates(
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
    @JsonView(Views.User.class) // Admin görünümleri
    public List<NewsDTO> getLikedNewsByUser(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
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
    @JsonView(Views.User.class) // Admin görünümleri
    public List<NewsDTO> getPersonalizedNews(@AuthenticationPrincipal UserDetails userDetails, @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws UserNotFoundException {
        return newsService.getPersonalizedNews(userDetails.getUsername(), platform);
    }


    @GetMapping("/statistics")
    public List<NewsStatistics> getMonthlyNewsStatistics(@AuthenticationPrincipal UserDetails userDetails) throws AdminNotFoundException, UnauthorizedAreaException {

        if (userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();
        return newsService.getMonthlyNewsStatistics(userDetails.getUsername());
    }

    @GetMapping("/admin/by-category")//Boş liste döndürüyor
    @JsonView(Views.Admin.class) // Admin görünümleri
    public List<NewsDTO> getNewsByCategoryForAdmin(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(name = "category") NewsType category,
            @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws AdminNotFoundException {
        // Burada isAdmin kontrolü opsiyonel olabilir çünkü endpoint admin için.
        return newsService.getNewsByCategoryForAdmin(userDetails.getUsername(), category, platform);
    }

    @GetMapping("/by-category")
    @JsonView(Views.User.class) // Admin görünümleri
    public List<NewsDTO> getNewsByCategoryForUser(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(name = "category") NewsType category,
            @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws UserNotFoundException {
        return newsService.getNewsByCategoryForUser(userDetails.getUsername(), category, platform);
    }

    // Kullanıcı haber geçmişi (kim ne zaman neyi okudu)
    @GetMapping("/view-history")
    public List<NewsHistoryDTO> getNewsViewHistory(@AuthenticationPrincipal UserDetails userDetails, @RequestParam(name = "platform", required = false) PlatformType platform
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
    @JsonView(Views.User.class) // Admin görünümleri
    public List<NewsDTO> getSuggestedNews(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(name = "platform", required = false) PlatformType platform
    ) throws UserNotFoundException {
        return newsService.getSuggestedNews(userDetails.getUsername(), platform);
    }

}


