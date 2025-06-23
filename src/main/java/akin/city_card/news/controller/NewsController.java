package akin.city_card.news.controller;

import akin.city_card.news.core.request.*;
import akin.city_card.news.core.response.AdminNewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.core.response.UserNewsDTO;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.news.service.abstracts.NewsService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;


import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/news")
@RequiredArgsConstructor
public class NewsController {

    private final NewsService newsService;

    @GetMapping("/")
    public DataResponseMessage<?> getAll(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"))) {
            return newsService.getAllForAdmin(userDetails.getUsername()); // AdminNewsDTO listesi
        } else {
            return newsService.getAllForUser(userDetails.getUsername()); // UserNewsDTO listesi
        }
    }


    @PostMapping("/create")
    public ResponseMessage createNews(@AuthenticationPrincipal UserDetails userDetails,
                                      @Valid @RequestBody CreateNewsRequest news) {
        return newsService.createNews(userDetails.getUsername(), news);
    }

    @PutMapping("/{id}/soft-delete")
    public ResponseMessage softDeleteNews(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id) {
        return newsService.softDeleteNews(userDetails.getUsername(), id);
    }

    @PutMapping("/{id}/update")
    public ResponseMessage updateNews(@AuthenticationPrincipal UserDetails userDetails,
                                      @RequestBody UpdateNewsRequest updatedNews) {
        return newsService.updateNews(userDetails.getUsername(), updatedNews);
    }

    @GetMapping("/{id}")
    public DataResponseMessage<?> getNewsById(@AuthenticationPrincipal UserDetails userDetails,
                                              @PathVariable Long id) {

        boolean isAdmin = userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));

        if (isAdmin) {
            return newsService.getNewsByIdForAdmin(userDetails.getUsername(), id); // AdminNewsDTO
        } else {
            return newsService.getNewsByIdForUser(userDetails.getUsername(), id); // UserNewsDTO
        }
    }


    @GetMapping("/active")
    public DataResponseMessage<?> getActiveNews(@AuthenticationPrincipal UserDetails userDetails,
                                                @RequestParam(required = false) PlatformType platform,
                                                @RequestParam(required = false) NewsType type) {

        boolean isAdmin = userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));

        if (isAdmin) {
            return newsService.getActiveNewsForAdmin(platform, type, userDetails.getUsername()); // List<AdminNewsDTO>
        } else {
            return newsService.getActiveNewsForUser(platform, type, userDetails.getUsername()); // List<UserNewsDTO>
        }
    }


    @PutMapping("/{id}/activate")
    public ResponseMessage activateNews(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id) {
        return newsService.activateNews(userDetails.getUsername(), id);
    }

    @GetMapping("/between-dates")
    public DataResponseMessage<List<AdminNewsDTO>> getNewsBetweenDates(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {
        return newsService.getNewsBetweenDates(userDetails.getUsername(), start, end);
    }

    @GetMapping("/liked")
    public DataResponseMessage<List<UserNewsDTO>> getLikedNewsByUser(@AuthenticationPrincipal UserDetails userDetails) {
        return newsService.getLikedNewsByUser(userDetails.getUsername());
    }

    @PostMapping("/{newsId}/like")
    public ResponseMessage likeNews(@PathVariable Long newsId, @AuthenticationPrincipal UserDetails userDetails) {
        return newsService.likeNews(newsId, userDetails.getUsername());
    }

    @DeleteMapping("/{newsId}/unlike")
    public ResponseMessage unlikeNews(@PathVariable Long newsId, @AuthenticationPrincipal UserDetails userDetails) {
        return newsService.unlikeNews(newsId, userDetails.getUsername());
    }

    @GetMapping("/personalized")
    public DataResponseMessage<List<UserNewsDTO>> getPersonalizedNews(@AuthenticationPrincipal UserDetails userDetails) {
        return newsService.getPersonalizedNews(userDetails.getUsername());
    }


    @GetMapping("/statistics")
    public DataResponseMessage<List<NewsStatistics>> getTopNewsStatistics(@AuthenticationPrincipal UserDetails userDetails) {
        return newsService.getTopNewsStatistics(userDetails.getUsername());
    }

    // Kategoriye göre haber listeleme
    @GetMapping("/by-category")
    public DataResponseMessage<List<?>> getNewsByCategory(@AuthenticationPrincipal UserDetails userDetails, @RequestParam NewsType category) {
        boolean isAdmin = userDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        if (isAdmin) {
            return newsService.getNewsByCategoryForAdmin(userDetails.getUsername(), category);
        }
        return newsService.getNewsByCategoryForUser(userDetails.getUsername(), category);

    }

    // Kullanıcı haber geçmişi (kim ne zaman neyi okudu)
    @GetMapping("/view-history")
    public DataResponseMessage<List<NewsHistoryDTO>> getNewsViewHistory(@AuthenticationPrincipal UserDetails userDetails) {
        return newsService.getNewsViewHistory(userDetails.getUsername());
    }

    // Haber görüntülendiğinde otomatik olarak history kaydı yapılması (genellikle frontend'de tetiklenir)
    @PostMapping("/{newsId}/view")
    public void viewNews(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long newsId) {
         newsService.recordNewsView(userDetails.getUsername(), newsId);
    }

    // Önerilen haberler (kategorilere göre kullanıcıya özel)
    @GetMapping("/suggested")
    public DataResponseMessage<List<UserNewsDTO>> getSuggestedNews(@AuthenticationPrincipal UserDetails userDetails) {
        return newsService.getSuggestedNews(userDetails.getUsername());
    }
}


