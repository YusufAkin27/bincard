package akin.city_card.news.controller;

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
import akin.city_card.news.service.abstracts.NewsService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.LocalDate;
import java.util.concurrent.ExecutionException;

@RestController
@RequestMapping("/v1/api/news")
@RequiredArgsConstructor
public class NewsController {

    private final NewsService newsService;

    @GetMapping("/")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('NEWS_ADMIN') or hasAuthority('SUPERADMIN')")
    public Page<AdminNewsDTO> getAll(@AuthenticationPrincipal UserDetails userDetails,
                                     @RequestParam(name = "platform", required = false) PlatformType platform,
                                     Pageable pageable)
            throws AdminNotFoundException, UnauthorizedAreaException {
        if (!isAdminOrSuperAdmin(userDetails)) throw new UnauthorizedAreaException();

        return newsService.getAllForAdmin(userDetails.getUsername(), platform, pageable);
    }


    public boolean isAdminOrSuperAdmin(UserDetails userDetails) {
        if (userDetails == null) return false;
        return userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ADMIN_ALL") || role.equals("SUPERADMIN") || role.equals("NEWS_ADMIN"));
    }

    @PostMapping(value = "/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('NEWS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage createNews(@AuthenticationPrincipal UserDetails userDetails,
                                      @Valid @ModelAttribute CreateNewsRequest news)
            throws AdminNotFoundException, UnauthorizedAreaException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException {
        if (!isAdminOrSuperAdmin(userDetails)) throw new UnauthorizedAreaException();

        return newsService.createNews(userDetails.getUsername(), news);
    }

    @PutMapping("/{id}/soft-delete")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('NEWS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage softDeleteNews(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id)
            throws NewsNotFoundException, AdminNotFoundException, UnauthorizedAreaException {
        if (!isAdminOrSuperAdmin(userDetails)) throw new UnauthorizedAreaException();

        return newsService.softDeleteNews(userDetails.getUsername(), id);
    }

    @PutMapping(value = "/update", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('NEWS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage updateNews(@AuthenticationPrincipal UserDetails userDetails,
                                      @Valid @ModelAttribute UpdateNewsRequest request)
            throws NewsNotFoundException, AdminNotFoundException, UnauthorizedAreaException, NewsIsNotActiveException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException {
        if (!isAdminOrSuperAdmin(userDetails)) throw new UnauthorizedAreaException();


        return newsService.updateNews(userDetails.getUsername(), request);
    }

    @GetMapping("/admin/{id}")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('NEWS_ADMIN') or hasAuthority('SUPERADMIN')")
    public AdminNewsDTO getNewsByIdForAdmin(@AuthenticationPrincipal UserDetails userDetails,
                                            @PathVariable Long id)
            throws AdminNotFoundException, NewsNotFoundException, NewsIsNotActiveException, UnauthorizedAreaException {
        if (!isAdminOrSuperAdmin(userDetails)) throw new UnauthorizedAreaException();

        return newsService.getNewsByIdForAdmin(userDetails.getUsername(), id);
    }

    // Anonim kullanıcılar da erişebilir
    @GetMapping("/{id}")
    public UserNewsDTO getNewsByIdForUser(@AuthenticationPrincipal UserDetails userDetails,
                                          @PathVariable Long id,
                                          @RequestParam(name = "platform") PlatformType platform,
                                          HttpServletRequest request)
            throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException {

        String username = userDetails != null ? userDetails.getUsername() : null;
        String clientIp = getClientIpAddress(request);
        String sessionId = request.getSession().getId();
        String userAgent = request.getHeader("User-Agent"); // ✅ User-Agent bilgisi

        if (username != null) {
            newsService.recordNewsView(username, id);
        } else {
            newsService.recordAnonymousNewsView(clientIp, id, userAgent, sessionId);
        }

        return newsService.getNewsByIdForUser(username, platform, id, clientIp, sessionId, userAgent);
    }


    @GetMapping("/active")
    public ResponseEntity<PageDTO<UserNewsDTO>> getActiveNewsForUser(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam PlatformType platform,
            @RequestParam(required = false) NewsType type,
            Pageable pageable,
            HttpServletRequest request) throws UserNotFoundException {

        String username = userDetails != null ? userDetails.getUsername() : null;
        String clientIp = getClientIpAddress(request);

        PageDTO<UserNewsDTO> result = newsService.getActiveNewsForUser(platform, type, username, clientIp, pageable);

        return ResponseEntity.ok(result);
    }

    @GetMapping("/active-admin")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('NEWS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<PageDTO<AdminNewsDTO>> getActiveNewsForAdmin(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(required = false) PlatformType platform,
            @RequestParam(required = false) NewsType type,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size)
            throws AdminNotFoundException, UnauthorizedAreaException {

        if (userDetails == null || userDetails.getAuthorities().stream()
                .noneMatch(a -> a.getAuthority().equals("ADMIN"))) {
            throw new UnauthorizedAreaException();
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("priority").descending()
                .and(Sort.by("createdAt").descending()));

        PageDTO<AdminNewsDTO> result = newsService.getActiveNewsForAdmin(platform, type, userDetails.getUsername(), pageable);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/between-dates")
    public ResponseEntity<PageDTO<UserNewsDTO>> getNewsBetweenDates(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end,
            @RequestParam(name = "platform", required = false) PlatformType platform,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) throws AdminNotFoundException, UnauthorizedAreaException {

        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN"))) {
            throw new UnauthorizedAreaException();
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("startDate").descending());

        PageDTO<UserNewsDTO> result = newsService.getNewsBetweenDates(
                userDetails.getUsername(),
                start.atStartOfDay(),
                end.atTime(23, 59, 59, 999_000_000),
                platform,
                pageable
        );

        return ResponseEntity.ok(result);
    }


    @GetMapping("/liked")
    public ResponseEntity<PageDTO<UserNewsDTO>> getLikedNewsByUser(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size)
            throws UserNotFoundException, UnauthorizedAreaException {

        if (userDetails == null) {
            throw new UnauthorizedAreaException();
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        PageDTO<UserNewsDTO> result = newsService.getLikedNewsByUser(userDetails.getUsername(), pageable);
        return ResponseEntity.ok(result);
    }


    // Giriş yapmış kullanıcılar için
    @PostMapping("/{newsId}/like")
    public ResponseMessage likeNews(@PathVariable Long newsId,
                                    @AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException, OutDatedNewsException, NewsAlreadyLikedException, UnauthorizedAreaException {
        if (userDetails == null) throw new UnauthorizedAreaException();

        newsService.recordNewsView(userDetails.getUsername(), newsId);

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


    @GetMapping("/statistics")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('NEWS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<PageDTO<NewsStatistics>> getMonthlyNewsStatistics(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size)
            throws AdminNotFoundException, UnauthorizedAreaException {

        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();

        Pageable pageable = PageRequest.of(page, size);
        PageDTO<NewsStatistics> result = newsService.getMonthlyNewsStatistics(userDetails.getUsername(), pageable);
        return ResponseEntity.ok(result);
    }


    @GetMapping("/admin/by-category")
    public ResponseEntity<PageDTO<UserNewsDTO>> getNewsByCategoryForAdmin(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(name = "category") NewsType category,
            @RequestParam(name = "platform", required = false) PlatformType platform,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) throws AdminNotFoundException, UnauthorizedAreaException {

        if (userDetails == null || userDetails.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ADMIN")))
            throw new UnauthorizedAreaException();

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        PageDTO<UserNewsDTO> result = newsService.getNewsByCategoryForAdmin(userDetails.getUsername(), category, platform, pageable);
        return ResponseEntity.ok(result);
    }


    @GetMapping("/by-category")
    public ResponseEntity<PageDTO<UserNewsDTO>> getNewsByCategoryForUser(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(name = "category") NewsType category,
            @RequestParam(name = "platform") PlatformType platform,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            HttpServletRequest request
    ) throws UserNotFoundException {
        String username = userDetails != null ? userDetails.getUsername() : null;
        String clientIp = getClientIpAddress(request);
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        PageDTO<UserNewsDTO> result = newsService.getNewsByCategoryForUser(username, category, platform, clientIp, pageable);
        return ResponseEntity.ok(result);
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