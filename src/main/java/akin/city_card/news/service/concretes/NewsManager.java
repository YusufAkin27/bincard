package akin.city_card.news.service.concretes;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.news.core.converter.NewsConverter;
import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.NewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
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
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
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
    public List<NewsDTO> getAllForAdmin(String username, PlatformType platform) throws AdminNotFoundException {

        return newsRepository.findAll().stream()
                .filter(news -> platform == null || news.getPlatform().equals(platform))
                .map(news -> newsConverter.toNewsDTO(news, false, false))
                .toList();
    }


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
    public NewsDTO getNewsByIdForAdmin(String username, Long id) throws NewsIsNotActiveException, NewsNotFoundException, AdminNotFoundException {
        News news = newsRepository.findById(id).orElseThrow(NewsNotFoundException::new);
        return newsConverter.toNewsDTO(news, false, false);

    }


    @Override
    public NewsDTO getActiveNewsForAdmin(PlatformType platform, NewsType type, String username) throws AdminNotFoundException {
        LocalDateTime now = LocalDateTime.now();

        List<News> filteredNews = newsRepository.findAll().stream()
                .filter(News::isActive)
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .filter(news -> platform == null || news.getPlatform() == platform || news.getPlatform() == PlatformType.ALL)
                .filter(news -> type == null || news.getType() == type)
                .toList();

        return (NewsDTO) filteredNews.stream()
                .sorted((n1, n2) -> {
                    int cmp = n2.getPriority().compareTo(n1.getPriority());
                    if (cmp == 0) {
                        if (n2.getCreatedAt() == null) return -1;
                        if (n1.getCreatedAt() == null) return 1;
                        return n2.getCreatedAt().compareTo(n1.getCreatedAt());
                    }
                    return cmp;
                })
                .map(news -> newsConverter.toNewsDTO(news, false, false));
    }


    private boolean checkIfLikedByUser(News news, User user) {
        return newsLikeRepository.existsByUserIdAndNewsId(user.getId(), news.getId());
    }

    private boolean checkIfViewedByUser(News news, User user) {
        return newsViewHistoryRepository.existsByUserIdAndNewsId(user.getId(), news.getId());
    }


    @Override
    public List<NewsDTO> getNewsBetweenDates(String username, LocalDateTime start, LocalDateTime end, PlatformType platform) throws AdminNotFoundException {

        if (start == null || end == null) {
            List.of();
        }

        List<News> newsBetweenDates = newsRepository.findAll().stream()
                .filter(news -> news.getStartDate() != null)
                .filter(news -> platform == null || news.getPlatform().equals(platform))
                .filter(news -> !news.getStartDate().isBefore(start) && !news.getStartDate().isAfter(end))
                .toList();

        return newsBetweenDates.stream()
                .map(news -> newsConverter.toNewsDTO(news, false, false))
                .toList();
    }


    @Override
    public List<NewsDTO> getLikedNewsByUser(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);


        List<NewsLike> newsLikes = user.getLikedNews();
        LocalDateTime now = LocalDateTime.now();

        return newsLikes.stream()
                .map(NewsLike::getNews)
                .filter(News::isActive)
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .map(news -> newsConverter.toNewsDTO(news, true, true)) // likedByUser = true, viewedByUser = false
                .toList();
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
    public List<NewsDTO> getPersonalizedNews(String username, PlatformType platform) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        if (user == null) {
            return List.of();
        }

        Set<NewsType> likedTypes = user.getLikedNews().stream()
                .map(like -> like.getNews().getType())
                .collect(Collectors.toSet());

        Set<NewsPriority> likedPriorities = user.getLikedNews().stream()
                .map(like -> like.getNews().getPriority())
                .collect(Collectors.toSet());

        Set<NewsType> viewedTypes = user.getViewedNews().stream()
                .map(view -> view.getNews().getType())
                .collect(Collectors.toSet());

        Set<NewsPriority> viewedPriorities = user.getViewedNews().stream()
                .map(view -> view.getNews().getPriority())
                .collect(Collectors.toSet());

        LocalDateTime now = LocalDateTime.now();

        List<News> activeNews = newsRepository.findAll().stream()
                .filter(News::isActive)
                .filter(news -> platform == null || news.getPlatform().equals(platform))
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .toList();

        Set<Long> likedNewsIds = user.getLikedNews().stream()
                .map(like -> like.getNews().getId())
                .collect(Collectors.toSet());

        List<NewsDTO> personalizedNews = activeNews.stream()
                .map(news -> {
                    int score = 0;
                    if (likedTypes.contains(news.getType())) score += 3;
                    if (likedPriorities.contains(news.getPriority())) score += 2;
                    if (viewedTypes.contains(news.getType())) score += 2;
                    if (viewedPriorities.contains(news.getPriority())) score += 1;

                    boolean likedByUser = likedNewsIds.contains(news.getId());
                    boolean viewedByUser = newsViewHistoryRepository.existsByUserAndNews(user, news);

                    return new AbstractMap.SimpleEntry<>(newsConverter.toNewsDTO(news, likedByUser, viewedByUser), score);
                })
                .filter(entry -> entry.getValue() > 0)
                .sorted((e1, e2) -> Integer.compare(e2.getValue(), e1.getValue())) // Skora göre azalan
                .map(Map.Entry::getKey)
                .toList();

        return personalizedNews;
    }


    @Override
    public List<NewsStatistics> getMonthlyNewsStatistics(String username) throws AdminNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null || !admin.getRoles().contains(Role.ADMIN)) {
            return List.of();
        }
        LocalDateTime startOfMonth = LocalDateTime.now().withDayOfMonth(1);
        List<NewsLike> likesThisMonth = newsLikeRepository.findByLikedAtAfter(startOfMonth);
        List<NewsViewHistory> viewsThisMonth = newsViewHistoryRepository.findByViewedAtAfter(startOfMonth);
        List<News> allNews = newsRepository.findAll();
        return allNews.stream()
                .map(news -> newsConverter.toDetailedStatistics(news, likesThisMonth, viewsThisMonth))
                .sorted(Comparator.comparingInt(NewsStatistics::getViewCountThisMonth).reversed())
                .toList();
    }


    @Override
    public List<NewsDTO> getNewsByCategoryForAdmin(String username, NewsType category, PlatformType platform) {
        List<News> newsList = newsRepository.findByTypeAndActiveTrue(category);
        return newsList.stream()
                .filter(news -> platform == null || news.getPlatform().equals(platform))
                .map(news -> newsConverter.toNewsDTO(news, false, false))
                .toList();
    }


    @Override
    public List<NewsHistoryDTO> getNewsViewHistory(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        LocalDateTime now = LocalDateTime.now();

        return
                user.getViewedNews().stream()
                        .filter(view -> {
                            News news = view.getNews();
                            return news != null &&
                                    news.isActive() &&
                                    (news.getEndDate() == null || news.getEndDate().isAfter(now));
                        })
                        .sorted(Comparator.comparing(NewsViewHistory::getViewedAt).reversed())
                        .map(newsConverter::toHistoryDTO)
                        .toList();

    }

    @Transactional
    public NewsDTO getNewsByIdForUser(String username, Long id, String clientIp, String sessionId, String userAgent)
            throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException {

        News news = newsRepository.findById(id)
                .orElseThrow(NewsNotFoundException::new);

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
                anonView.setSessionId(sessionId); // 🟢 Burada ekledik!
                anonView.setUserAgent(userAgent);
                anonView.setViewedAt(LocalDateTime.now());
                anonymousNewsViewHistoryRepository.save(anonView);
            }
        }

        news.setViewCount(news.getViewCount() + 1);
        newsRepository.save(news);

        return newsConverter.toNewsDTO(news, liked, viewed);
    }


    @Override
    public List<NewsDTO> getActiveNewsForUser(PlatformType platform, NewsType type, String username, String clientIp)
            throws UserNotFoundException {

        LocalDateTime now = LocalDateTime.now();

        List<News> allActiveNews = newsRepository.findAll().stream()
                .filter(News::isActive)
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .toList();

        if (username == null) {
            return allActiveNews.stream()
                    .map(news -> newsConverter.toNewsDTO(news, false, false))
                    .toList();
        }

        Optional<User> optionalUser = userRepository.findByUserNumber(username);
        if (optionalUser.isEmpty()) {
            throw new UserNotFoundException();
        }

        User user = optionalUser.get();
        List<NewsLike> likedNews = user.getLikedNews();
        boolean shouldScore = (platform != null || type != null || !likedNews.isEmpty());

        if (!shouldScore) {
            return allActiveNews.stream()
                    .map(news -> {
                        boolean likedByUser = checkIfLikedByUser(news, user);
                        boolean viewedByUser = checkIfViewedByUser(news, user);
                        return newsConverter.toNewsDTO(news, likedByUser, viewedByUser);
                    })
                    .toList();
        }

        Set<NewsType> preferredTypes = likedNews.stream()
                .map(like -> like.getNews().getType())
                .collect(Collectors.toSet());

        Set<NewsPriority> preferredPriorities = likedNews.stream()
                .map(like -> like.getNews().getPriority())
                .collect(Collectors.toSet());


        return allActiveNews.stream()
                .map(news -> {
                    boolean likedByUser = checkIfLikedByUser(news, user);
                    boolean viewedByUser = checkIfViewedByUser(news, user);

                    int score = 0;

                    if (type != null && news.getType() == type) score += 3;
                    if (platform != null && (news.getPlatform() == platform || news.getPlatform().name().equals("ALL")))
                        score += 3;

                    if (preferredTypes.contains(news.getType())) score += 2;
                    if (preferredPriorities.contains(news.getPriority())) score += 1;

                    NewsDTO dto = newsConverter.toNewsDTO(news, likedByUser, viewedByUser);
                    return new AbstractMap.SimpleEntry<>(dto, score);
                })
                .sorted((e1, e2) -> Integer.compare(e2.getValue(), e1.getValue()))
                .map(Map.Entry::getKey)
                .toList();
    }


    @Override
    public List<NewsDTO> getNewsByCategoryForUser(String username, NewsType category, PlatformType platform, String clientIp)
            throws UserNotFoundException {

        List<News> newsList = newsRepository.findByTypeAndActiveTrue(category)
                .stream()
                .filter(news -> platform == null || news.getPlatform().equals(platform) || news.getPlatform().name().equals("ALL"))
                .toList();

        if (username == null) {
            return newsList.stream()
                    .map(news -> newsConverter.toNewsDTO(news, false, false))
                    .toList();
        }

        Optional<User> optionalUser = userRepository.findByUserNumber(username);
        if (optionalUser.isEmpty()) {
            throw new UserNotFoundException();
        }

        User user = optionalUser.get();

        Set<Long> likedNewsIds = user.getLikedNews().stream()
                .map(like -> like.getNews().getId())
                .collect(Collectors.toSet());

        return newsList.stream()
                .map(news -> {
                    boolean liked = likedNewsIds.contains(news.getId());
                    boolean viewed = newsViewHistoryRepository.existsByUserAndNews(user, news);
                    return newsConverter.toNewsDTO(news, liked, viewed);
                })
                .toList();
    }


    @Override
    public List<NewsDTO> getSuggestedNews(String username, PlatformType platformType, String clientIp) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        if (user == null) {
            return List.of();
        }
        Set<NewsType> likedTypes = new HashSet<>();
        Set<NewsPriority> likedPriorities = new HashSet<>();

        Set<NewsType> viewedTypes = new HashSet<>();
        Set<NewsPriority> viewedPriorities = new HashSet<>();

        for (NewsLike like : user.getLikedNews()) {
            likedTypes.add(like.getNews().getType());
            likedPriorities.add(like.getNews().getPriority());
        }

        for (NewsViewHistory view : user.getViewedNews()) {
            viewedTypes.add(view.getNews().getType());
            viewedPriorities.add(view.getNews().getPriority());
        }

        LocalDateTime now = LocalDateTime.now();
        List<News> activeNews = newsRepository.findAll().stream()
                .filter(News::isActive)
                .filter(news ->
                        platformType == null ||
                                news.getPlatform() == platformType ||
                                news.getPlatform() == PlatformType.ALL
                )
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .toList();

        Set<Long> likedNewsIds = user.getLikedNews().stream()
                .map(like -> like.getNews().getId())
                .collect(Collectors.toSet());


        return activeNews.stream()
                .map(news -> {
                    int score = 0;

                    if (likedTypes.contains(news.getType())) score += 3;
                    if (likedPriorities.contains(news.getPriority())) score += 2;

                    // Görüntülenme bazlı
                    if (viewedTypes.contains(news.getType())) score += 2;
                    if (viewedPriorities.contains(news.getPriority())) score += 1;

                    boolean likedByUser = likedNewsIds.contains(news.getId());
                    boolean viewedByUser = newsViewHistoryRepository.existsByUserAndNews(user, news);

                    NewsDTO dto = newsConverter.toNewsDTO(news, likedByUser, viewedByUser);
                    return new AbstractMap.SimpleEntry<>(dto, score);
                })
                .sorted((e1, e2) -> Integer.compare(e2.getValue(), e1.getValue()))
                .map(Map.Entry::getKey)
                .toList();
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
        }

        news.setViewCount(news.getViewCount() + 1);
        newsRepository.save(news);
    }


    @Override
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

    @Override
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

    @Override
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

    @Override
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


}
