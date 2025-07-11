package akin.city_card.news.service.concretes;
import akin.city_card.news.core.response.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.news.core.converter.NewsConverter;
import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.exceptions.*;
import akin.city_card.news.model.*;
import akin.city_card.news.repository.AnonymousNewsViewHistoryRepository;
import akin.city_card.news.repository.NewsLikeRepository;
import akin.city_card.news.repository.NewsRepository;
import akin.city_card.news.repository.NewsViewHistoryRepository;
import akin.city_card.news.service.abstracts.NewsService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.Role;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class NewsManager implements NewsService {
    private final NewsRepository newsRepository;
    private final NewsLikeRepository newsLikeRepository;
    private final NewsViewHistoryRepository newsViewHistoryRepository;
    private final NewsConverter newsConverter;
    private final AdminRepository adminRepository;
    private final UserRepository userRepository;
    private final MediaUploadService mediaUploadService;
    private final AnonymousNewsViewHistoryRepository anonymousNewsViewHistoryRepository;



    @Override
    @Transactional
    public ResponseMessage createNews(String username, CreateNewsRequest createNewsRequest)
            throws AdminNotFoundException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException {

        News news = newsConverter.fromCreateRequest(createNewsRequest);

        if (createNewsRequest.getImage() != null && !createNewsRequest.getImage().isEmpty()) {
            String imageUrl = mediaUploadService.uploadAndOptimizeMedia(createNewsRequest.getImage()).get();
            news.setImage(imageUrl);
        }
        if (createNewsRequest.getThumbnail() != null && !createNewsRequest.getThumbnail().isEmpty()) {
            String imageUrl = mediaUploadService.uploadAndOptimizeMedia(createNewsRequest.getThumbnail()).get();
            news.setThumbnail(imageUrl);
        }
        newsRepository.save(news);
        return new ResponseMessage("haber eklendi", true);
    }

    @Override
    public ResponseMessage softDeleteNews(String username, Long id) throws NewsNotFoundException, AdminNotFoundException {
        News news = newsRepository.findById(id).orElseThrow(NewsNotFoundException::new);
        news.setActive(false);
        newsRepository.save(news);
        return new ResponseMessage("haber silindi", true);
    }

    @Override
    public ResponseMessage updateNews(String username, UpdateNewsRequest updatedNews) throws AdminNotFoundException, NewsNotFoundException, NewsIsNotActiveException, PhotoSizeLargerException, IOException, ExecutionException, InterruptedException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException {
        News news = newsRepository.findById(updatedNews.getId())
                .orElseThrow(NewsNotFoundException::new);


        newsConverter.updateEntityFromDTO(news, updatedNews);


        if (updatedNews.getImage() != null && !updatedNews.getImage().isEmpty()) {
            String imageUrl = mediaUploadService.uploadAndOptimizeMedia(updatedNews.getImage()).get();
            news.setImage(imageUrl);
        }


        newsRepository.save(news);

        return new ResponseMessage("Haber başarıyla güncellendi", true);
    }


    @Override
    public AdminNewsDTO getNewsByIdForAdmin(String username, Long id) throws NewsIsNotActiveException, NewsNotFoundException, AdminNotFoundException {
        News news = newsRepository.findById(id).orElseThrow(NewsNotFoundException::new);
        return newsConverter.toAdminNewsDTO(news);

    }


    @Override
    public PageDTO<AdminNewsDTO> getActiveNewsForAdmin(PlatformType platform, NewsType type, String username, Pageable pageable)
            throws AdminNotFoundException {

        LocalDateTime now = LocalDateTime.now();

        List<News> allNews = newsRepository.findAll(); // filtrelemeden önce tüm veri alınır

        List<News> filtered = allNews.stream()
                .filter(News::isActive)
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .filter(news -> platform == null || news.getPlatform() == platform || news.getPlatform() == PlatformType.ALL)
                .filter(news -> type == null || news.getType() == type)
                .sorted((n1, n2) -> {
                    int cmp = n2.getPriority().compareTo(n1.getPriority());
                    if (cmp == 0 && n1.getCreatedAt() != null && n2.getCreatedAt() != null) {
                        return n2.getCreatedAt().compareTo(n1.getCreatedAt());
                    }
                    return cmp;
                })
                .toList();

        int start = (int) pageable.getOffset();
        int end = Math.min((start + pageable.getPageSize()), filtered.size());

        List<AdminNewsDTO> pageContent = filtered.subList(start, end)
                .stream()
                .map(newsConverter::toAdminNewsDTO)
                .toList();

        Page<AdminNewsDTO> page = new org.springframework.data.domain.PageImpl<>(pageContent, pageable, filtered.size());

        return new PageDTO<>(page);
    }

    @Override
    public PageDTO<UserNewsDTO> getNewsBetweenDates(String username, LocalDateTime start, LocalDateTime end, PlatformType platform, Pageable pageable) {

        List<News> filtered = newsRepository.findAll().stream()
                .filter(news -> news.getStartDate() != null)
                .filter(news -> platform == null || news.getPlatform() == platform || news.getPlatform() == PlatformType.ALL)
                .filter(news -> !news.getStartDate().isBefore(start) && !news.getStartDate().isAfter(end))
                .sorted(Comparator.comparing(News::getStartDate).reversed())
                .toList();

        int offset = (int) pageable.getOffset();
        int endIndex = Math.min(offset + pageable.getPageSize(), filtered.size());

        List<UserNewsDTO> content = filtered.subList(offset, endIndex).stream()
                .map(news -> newsConverter.toNewsDTO(news, false, false))
                .toList();

        Page<UserNewsDTO> page = new PageImpl<>(content, pageable, filtered.size());

        return new PageDTO<>(page);
    }



    private boolean checkIfLikedByUser(News news, User user) {
        return newsLikeRepository.existsByUserIdAndNewsId(user.getId(), news.getId());
    }

    private boolean checkIfViewedByUser(News news, User user) {
        return newsViewHistoryRepository.existsByUserIdAndNewsId(user.getId(), news.getId());
    }





    @Override
    public PageDTO<UserNewsDTO> getLikedNewsByUser(String username, Pageable pageable) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        LocalDateTime now = LocalDateTime.now();

        List<News> likedActiveNews = user.getLikedNews().stream()
                .map(NewsLike::getNews)
                .filter(News::isActive)
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .sorted(Comparator.comparing(News::getCreatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .toList();

        int offset = (int) pageable.getOffset();
        int endIndex = Math.min(offset + pageable.getPageSize(), likedActiveNews.size());

        List<UserNewsDTO> pageContent = likedActiveNews.subList(offset, endIndex).stream()
                .map(news -> newsConverter.toNewsDTO(news, true, checkIfViewedByUser(news, user)))
                .toList();

        Page<UserNewsDTO> page = new PageImpl<>(pageContent, pageable, likedActiveNews.size());
        return new PageDTO<>(page);
    }



    @Override
    public ResponseMessage likeNews(Long newsId, String username) throws OutDatedNewsException, NewsIsNotActiveException, NewsNotFoundException, UserNotFoundException, NewsAlreadyLikedException {
        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        News news = newsRepository.findById(newsId)
                .orElseThrow(NewsNotFoundException::new);

        if (!news.isActive()) {
            throw new NewsIsNotActiveException(newsId + " ");
        }

        if (news.getEndDate() != null && news.getEndDate().isBefore(LocalDateTime.now())) {
            throw new OutDatedNewsException();
        }

        if (checkIfLikedByUser(news, user)) {
            throw new NewsAlreadyLikedException();
        }

        NewsLike newsLike = new NewsLike();
        newsLike.setNews(news);
        newsLike.setUser(user);
        newsLike.setLikedAt(LocalDateTime.now());

        newsLikeRepository.save(newsLike);

        user.getLikedNews().add(newsLike);
        userRepository.save(user);

        return new ResponseMessage("Haber beğenildi", true);
    }


    @Override
    public ResponseMessage unlikeNews(Long newsId, String username) throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException, OutDatedNewsException, NewsNotLikedException {
        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        News news = newsRepository.findById(newsId)
                .orElseThrow(NewsNotFoundException::new);

        if (!news.isActive()) {
            throw new NewsIsNotActiveException(newsId + " ");
        }

        if (news.getEndDate() != null && news.getEndDate().isBefore(LocalDateTime.now())) {
            throw new OutDatedNewsException();
        }

        if (!checkIfLikedByUser(news, user)) {
            throw new NewsNotLikedException();
        }

        newsLikeRepository.deleteByUserIdAndNewsId(user.getId(), news.getId());

        user.getLikedNews().removeIf(newsLike -> newsLike.getNews().equals(news));
        userRepository.save(user);

        return new ResponseMessage("Beğeni kaldırıldı", true);
    }





    @Override
    public PageDTO<NewsStatistics> getMonthlyNewsStatistics(String username, Pageable pageable)
            throws AdminNotFoundException {

        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null || !admin.getRoles().contains(Role.ADMIN)) {
            throw new AdminNotFoundException();
        }

        LocalDateTime startOfMonth = LocalDateTime.now().withDayOfMonth(1);

        List<NewsLike> likesThisMonth = newsLikeRepository.findByLikedAtAfter(startOfMonth);
        List<NewsViewHistory> viewsThisMonth = newsViewHistoryRepository.findByViewedAtAfter(startOfMonth);
        List<News> allNews = newsRepository.findAll();

        List<NewsStatistics> statisticsList = allNews.stream()
                .map(news -> newsConverter.toDetailedStatistics(news, likesThisMonth, viewsThisMonth))
                .sorted(Comparator.comparingInt(NewsStatistics::getViewCountThisMonth).reversed())
                .toList();

        // Sayfalama işlemi manuel
        int offset = (int) pageable.getOffset();
        int endIndex = Math.min(offset + pageable.getPageSize(), statisticsList.size());
        List<NewsStatistics> pagedList = statisticsList.subList(offset, endIndex);

        Page<NewsStatistics> page = new PageImpl<>(pagedList, pageable, statisticsList.size());
        return new PageDTO<>(page);
    }


    @Override
    public PageDTO<UserNewsDTO> getNewsByCategoryForAdmin(String username, NewsType category, PlatformType platform, Pageable pageable) {
        List<News> newsList = newsRepository.findByTypeAndActiveTrue(category).stream()
                .filter(news -> platform == null || news.getPlatform().equals(platform))
                .sorted(Comparator.comparing(News::getCreatedAt).reversed()) // opsiyonel sıralama
                .toList();

        int offset = (int) pageable.getOffset();
        int endIndex = Math.min(offset + pageable.getPageSize(), newsList.size());
        List<UserNewsDTO> pagedList = newsList.subList(offset, endIndex)
                .stream()
                .map(news -> newsConverter.toNewsDTO(news, false, false))
                .toList();

        Page<UserNewsDTO> page = new PageImpl<>(pagedList, pageable, newsList.size());
        return new PageDTO<>(page);
    }





    @Transactional
    public UserNewsDTO getNewsByIdForUser(String username,
                                          PlatformType platformType,
                                          Long id,
                                          String clientIp,
                                          String sessionId,
                                          String userAgent)
            throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException {

        News news = newsRepository.findById(id)
                .orElseThrow(NewsNotFoundException::new);

        if (news.getPlatform() != PlatformType.ALL && news.getPlatform() != platformType) {
            throw new NewsIsNotActiveException(id+"");
        }

        if (!news.isActive()) {
            throw new NewsIsNotActiveException("News with ID " + id + " is not active");
        }

        boolean liked = false;
        boolean viewed = false;

        if (username != null) {
            User user = userRepository.findByUserNumberWithViewedNews(username)
                    .orElseThrow(UserNotFoundException::new);

            viewed = newsViewHistoryRepository.existsByUserAndNews(user, news);
            if (!viewed) {
                NewsViewHistory viewHistory = new NewsViewHistory();
                viewHistory.setUser(user);
                viewHistory.setNews(news);
                viewHistory.setViewedAt(LocalDateTime.now());
                newsViewHistoryRepository.save(viewHistory);
                user.getViewedNews().add(viewHistory);
            }

            liked = newsLikeRepository.existsByUserAndNews(user, news);
        } else {
            boolean alreadyViewed = anonymousNewsViewHistoryRepository.existsByClientIpAndNews(clientIp, news);
            if (!alreadyViewed) {
                AnonymousNewsViewHistory anonView = new AnonymousNewsViewHistory();
                anonView.setNews(news);
                anonView.setClientIp(clientIp);
                anonView.setSessionId(sessionId);
                anonView.setUserAgent(userAgent);
                anonView.setViewedAt(LocalDateTime.now());
                anonymousNewsViewHistoryRepository.save(anonView);
            }
        }
        newsRepository.save(news);

        return newsConverter.toNewsDTO(news, liked, viewed);
    }





    @Override
    public PageDTO<UserNewsDTO> getNewsByCategoryForUser(String username, NewsType category, PlatformType platform, String clientIp, Pageable pageable) throws UserNotFoundException {

        List<News> filtered = newsRepository.findByTypeAndActiveTrue(category)
                .stream()
                .filter(news -> platform == null || news.getPlatform().equals(platform) || news.getPlatform() == PlatformType.ALL)
                .sorted(Comparator.comparing(News::getCreatedAt).reversed())
                .toList();

        int offset = (int) pageable.getOffset();
        int endIndex = Math.min(offset + pageable.getPageSize(), filtered.size());
        List<News> pageContent = filtered.subList(offset, endIndex);

        if (username == null) {
            List<UserNewsDTO> dtoList = pageContent.stream()
                    .map(news -> newsConverter.toNewsDTO(news, false, false))
                    .toList();
            return new PageDTO<>(new PageImpl<>(dtoList, pageable, filtered.size()));
        }

        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        Set<Long> likedIds = user.getLikedNews().stream()
                .map(like -> like.getNews().getId())
                .collect(Collectors.toSet());

        List<UserNewsDTO> personalizedDtos = pageContent.stream()
                .map(news -> {
                    boolean liked = likedIds.contains(news.getId());
                    boolean viewed = newsViewHistoryRepository.existsByUserAndNews(user, news);
                    return newsConverter.toNewsDTO(news, liked, viewed);
                })
                .toList();

        return new PageDTO<>(new PageImpl<>(personalizedDtos, pageable, filtered.size()));
    }



    @Override
    @Transactional
    public void recordNewsView(String username, Long newsId)
            throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException {

        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        News news = newsRepository.findById(newsId)
                .orElseThrow(NewsNotFoundException::new);

        if (!news.isActive()) {
            throw new NewsIsNotActiveException(newsId + "");
        }

        boolean alreadyViewed = newsViewHistoryRepository.existsByUserAndNews(user, news);
        if (!alreadyViewed) {
            NewsViewHistory newsViewHistory = new NewsViewHistory();
            newsViewHistory.setUser(user);
            newsViewHistory.setNews(news);
            newsViewHistory.setViewedAt(LocalDateTime.now());
            newsViewHistoryRepository.save(newsViewHistory);
            user.getViewedNews().add(newsViewHistory);

            news.setViewCount(news.getViewCount() + 1);
            newsRepository.save(news);
        }
    }




    @Transactional
    public void recordAnonymousNewsView(String clientIp, Long newsId, String userAgent, String sessionId)
            throws NewsIsNotActiveException, NewsNotFoundException {
        News news = newsRepository.findById(newsId).orElseThrow(NewsNotFoundException::new);

        if (!news.isActive()) {
            throw new NewsIsNotActiveException(newsId + " ");
        }

        AnonymousNewsViewHistory view = new AnonymousNewsViewHistory();
        view.setNews(news);
        view.setClientIp(clientIp);
        view.setUserAgent(userAgent);
        view.setSessionId(sessionId);
        view.setViewedAt(LocalDateTime.now());

        anonymousNewsViewHistoryRepository.save(view);
    }


    @Transactional
    public void activateScheduledNews() {
        LocalDateTime now = LocalDateTime.now();
        List<News> newsToActivate = newsRepository.findByStartDateBeforeAndActiveFalse(now);

        for (News news : newsToActivate) {
            news.setActive(true);
        }

        if (!newsToActivate.isEmpty()) {
            newsRepository.saveAll(newsToActivate);
        }
    }

    @Transactional
    public void deactivateExpiredNews() {
        LocalDateTime now = LocalDateTime.now();
        List<News> newsToDeactivate = newsRepository.findByEndDateBeforeAndActiveTrue(now);

        for (News news : newsToDeactivate) {
            news.setActive(false);
        }

        if (!newsToDeactivate.isEmpty()) {
            newsRepository.saveAll(newsToDeactivate);
        }
    }


    @Transactional
    public void performDailyStatusCheck() {
        LocalDateTime now = LocalDateTime.now();
        List<News> allNews = newsRepository.findAll();

        boolean updated = false;

        for (News news : allNews) {
            boolean shouldBeActive =
                    (news.getStartDate() == null || !news.getStartDate().isAfter(now)) &&
                            (news.getEndDate() == null || news.getEndDate().isAfter(now));

            if (shouldBeActive && !news.isActive()) {
                news.setActive(true);
                updated = true;
            } else if (!shouldBeActive && news.isActive()) {
                news.setActive(false);
                updated = true;
            }
        }

        if (updated) {
            newsRepository.saveAll(allNews);
        }
    }

    @Override
    public Page<AdminNewsDTO> getAllForAdmin(String username, PlatformType platform, Pageable pageable) throws AdminNotFoundException {
        Page<News> newsPage;

        if (platform == null) {
            newsPage = newsRepository.findAll(pageable);
        } else {
            newsPage = newsRepository.findByPlatform(platform, pageable);
        }

        return newsPage.map(newsConverter::toAdminNewsDTO);
    }

    @Override
    public PageDTO<UserNewsDTO> getActiveNewsForUser(PlatformType platform, NewsType type, String username, String clientIp, Pageable pageable) {
        Logger logger = LoggerFactory.getLogger(this.getClass());

        logger.info("getActiveNewsForUser çağrıldı -> platform={}, type={}, username={}, clientIp={}", platform, type, username, clientIp);

        LocalDateTime now = LocalDateTime.now();

        List<PlatformType> platformsToSearch = List.of(platform, PlatformType.ALL);
        Page<News> allActiveNews = newsRepository.findByPlatformInAndActiveTrueAndValidEndDate(platformsToSearch, now, pageable);

        Optional<User> optionalUser = username == null ? Optional.empty() : userRepository.findByUserNumber(username);
        User user = optionalUser.orElse(null);

        Set<Long> likedNewsIds = user != null ?
                user.getLikedNews().stream().map(like -> like.getNews().getId()).collect(Collectors.toSet()) :
                Collections.emptySet();

        Set<Long> viewedNewsIds = user != null ?
                user.getViewedNews().stream().map(view -> view.getNews().getId()).collect(Collectors.toSet()) :
                Collections.emptySet();

        Set<NewsType> preferredTypes = user != null ?
                user.getLikedNews().stream().map(like -> like.getNews().getType()).collect(Collectors.toSet()) :
                Collections.emptySet();

        Set<NewsPriority> preferredPriorities = user != null ?
                user.getLikedNews().stream().map(like -> like.getNews().getPriority()).collect(Collectors.toSet()) :
                Collections.emptySet();

        // Haberleri puanlamak ve sıralamak için liste oluşturuyoruz
        List<NewsWithScore> scoredNews = allActiveNews.getContent().stream()
                .map(news -> {
                    boolean likedByUser = likedNewsIds.contains(news.getId());
                    boolean viewedByUser = viewedNewsIds.contains(news.getId());

                    int score = 0;

                    // 🔹 Kullanıcının beğendiği tür en yüksek öncelik
                    if (preferredTypes.contains(news.getType())) score += 5;
                    if (preferredPriorities.contains(news.getPriority())) score += 2;

                    // 🔹 Kullanıcının daha önceki etkileşimleri
                    if (likedByUser) score += 3;
                    if (viewedByUser) score += 2;

                    // 🔹 Eğer query'den filtre geldiyse ekstra puan
                    if (type != null && news.getType() == type) score += 1;
                    if (platform != null && (news.getPlatform() == platform || news.getPlatform() == PlatformType.ALL)) score += 1;

                    return new NewsWithScore(
                            newsConverter.toNewsDTO(news, likedByUser, viewedByUser),
                            score
                    );
                })
                .sorted(Comparator.comparingInt(NewsWithScore::getScore).reversed())
                .collect(Collectors.toList());

        // Skorlanmış haberleri DTO'ya dönüştürüyoruz
        List<UserNewsDTO> sortedDtos = scoredNews.stream()
                .map(NewsWithScore::getUserNewsDto)
                .collect(Collectors.toList());

        // Yeni bir Page objesi oluşturuyoruz
        Page<UserNewsDTO> resultPage = new PageImpl<>(sortedDtos, pageable, allActiveNews.getTotalElements());
        return new PageDTO<>(resultPage);
    }


    @Getter
    @AllArgsConstructor
    private static class NewsWithScore {
        private UserNewsDTO userNewsDto;
        private int score;
    }





}