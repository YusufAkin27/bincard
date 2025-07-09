package akin.city_card.news.service.concretes;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.news.core.converter.NewsConverter;
import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.AdminNewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.core.response.UserNewsDTO;
import akin.city_card.news.exceptions.NewsIsNotActiveException;
import akin.city_card.news.exceptions.NewsNotFoundException;
import akin.city_card.news.exceptions.OutDatedNewsException;
import akin.city_card.news.model.*;
import akin.city_card.news.repository.NewsLikeRepository;
import akin.city_card.news.repository.NewsRepository;
import akin.city_card.news.repository.NewsViewHistoryRepository;
import akin.city_card.news.service.abstracts.NewsService;
import akin.city_card.response.DataResponseMessage;
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


    @Override
    public DataResponseMessage<List<AdminNewsDTO>> getAllForAdmin(String username, PlatformType platform) throws AdminNotFoundException {
        List<AdminNewsDTO> adminNewsDTOS = newsRepository.findAll().stream()
                .filter(news -> platform == null || news.getPlatform().equals(platform))
                .map(newsConverter::toAdminDTO)
                .toList();

        return new DataResponseMessage<>("Tüm haberler listelendi", true, adminNewsDTOS);
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
    public DataResponseMessage<?> getNewsByIdForAdmin(String username, Long id) throws NewsIsNotActiveException, NewsNotFoundException, AdminNotFoundException {
        News news = newsRepository.findById(id).orElseThrow(NewsNotFoundException::new);
        AdminNewsDTO adminNewsDTO = newsConverter.toAdminDTO(news);

        return new DataResponseMessage<>("haber", true, adminNewsDTO);
    }

    @Override
    public DataResponseMessage<?> getNewsByIdForUser(String username, Long id) throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException {
        User user = userRepository.findByUserNumber(username);
        News news = newsRepository.findById(id).orElseThrow(NewsNotFoundException::new);
        if (!news.isActive()) {
            throw new NewsIsNotActiveException(id + " ");
        }
        recordNewsView(username, id);
        NewsViewHistory newsViewHistory = new NewsViewHistory();
        newsViewHistory.setUser(user);
        newsViewHistory.setNews(news);
        newsViewHistory.setViewedAt(LocalDateTime.now());
        newsViewHistoryRepository.save(newsViewHistory);
        user.getViewedNews().add(newsViewHistory);
        UserNewsDTO newsDTO = newsConverter.toUserDTO(news, false, true);

        return new DataResponseMessage<>("haber", true, newsDTO);
    }

    @Override
    public DataResponseMessage<?> getActiveNewsForAdmin(PlatformType platform, NewsType type, String username) throws AdminNotFoundException {
        LocalDateTime now = LocalDateTime.now();

        List<News> filteredNews = newsRepository.findAll().stream()
                .filter(News::isActive)
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .filter(news -> platform == null || news.getPlatform() == platform || news.getPlatform() == PlatformType.ALL)
                .filter(news -> type == null || news.getType() == type)
                .toList();

        List<AdminNewsDTO> sortedNews = filteredNews.stream()
                .sorted((n1, n2) -> {
                    int cmp = n2.getPriority().compareTo(n1.getPriority());
                    if (cmp == 0) {
                        if (n2.getCreatedAt() == null) return -1;
                        if (n1.getCreatedAt() == null) return 1;
                        return n2.getCreatedAt().compareTo(n1.getCreatedAt());
                    }
                    return cmp;
                })
                .map(newsConverter::toAdminDTO)
                .toList();

        return new DataResponseMessage<>("Admin için aktif haberler", true, sortedNews);
    }

    @Override
    public DataResponseMessage<?> getActiveNewsForUser(PlatformType platform, NewsType type, String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);
        if (user == null) {
            throw new UserNotFoundException();
        }
/*
        List<NewsLike> likedNews = user.getLikedNews();

        LocalDateTime now = LocalDateTime.now();
        List<News> allActiveNews = newsRepository.findAll().stream()
                .filter(News::isActive)
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .toList();

        // Eğer hiçbir filtreleme veya beğeni yoksa, tüm haberleri döndür
        boolean shouldScore = (platform != null || type != null || !likedNews.isEmpty());

        List<UserNewsDTO> resultNews;

        if (!shouldScore) {
            // Tüm aktif haberleri döndür
            resultNews = allActiveNews.stream()
                    .map(news -> {
                        boolean likedByUser = false;
                        boolean viewedByUser = newsViewHistoryRepository.existsByUserAndNews(user, news);
                        return newsConverter.toUserDTO(news, likedByUser, viewedByUser);
                    })
                    .toList();
        } else {
            // Skorlama yapılacaksa
            Set<NewsType> preferredTypes = likedNews.stream()
                    .map(like -> like.getNews().getType())
                    .collect(Collectors.toSet());

            Set<NewsPriority> preferredPriorities = likedNews.stream()
                    .map(like -> like.getNews().getPriority())
                    .collect(Collectors.toSet());

            resultNews = allActiveNews.stream()
                    .map(news -> {
                        boolean likedByUser = likedNews.stream()
                                .anyMatch(like -> like.getNews().getId().equals(news.getId()));

                        boolean viewedByUser = newsViewHistoryRepository.existsByUserAndNews(user, news);

                        int score = 0;

                        if (type != null && news.getType() == type) score += 3;
                        if (platform != null && (news.getPlatform() == platform || news.getPlatform().name().equals("ALL")))
                            score += 3;

                        if (preferredTypes.contains(news.getType())) score += 2;
                        if (preferredPriorities.contains(news.getPriority())) score += 1;

                        UserNewsDTO dto = newsConverter.toUserDTO(news, likedByUser, viewedByUser);
                        return new AbstractMap.SimpleEntry<>(dto, score);
                    })
                    .sorted((e1, e2) -> Integer.compare(e2.getValue(), e1.getValue()))
                    .map(Map.Entry::getKey)
                    .toList();
        }

 */

        return new DataResponseMessage<>("Kişiye özel haberler", true, newsRepository.findAll().stream().map(news -> newsConverter.toUserDTO(news,
                checkIfLikedByUser(news,user),
                checkIfViewedByUser(news,user))).collect(Collectors.toList()));
    }

    private boolean checkIfLikedByUser(News news,User user) {
        // Kullanıcının ID'sine göre DB kontrolü yapılabilir
        return newsLikeRepository.existsByUserIdAndNewsId(user.getId(), news.getId());
    }

    private boolean checkIfViewedByUser(News news,User user) {
        return newsViewHistoryRepository.existsByUserIdAndNewsId(user.getId(), news.getId());
    }



    @Override
    public DataResponseMessage<List<AdminNewsDTO>> getNewsBetweenDates(String username, LocalDateTime start, LocalDateTime end, PlatformType platform) throws AdminNotFoundException {

        if (start == null || end == null) {
            return new DataResponseMessage<>("Başlangıç ve bitiş tarihleri zorunludur", false, null);
        }

        List<News> newsBetweenDates = newsRepository.findAll().stream()
                .filter(news -> news.getStartDate() != null)
                .filter(news -> platform == null || news.getPlatform().equals(platform))
                .filter(news -> !news.getStartDate().isBefore(start) && !news.getStartDate().isAfter(end))
                .toList();

        List<AdminNewsDTO> dtoList = newsBetweenDates.stream()
                .map(newsConverter::toAdminDTO)
                .toList();

        return new DataResponseMessage<>("Belirtilen tarihler arasındaki haberler", true, dtoList);
    }


    @Override
    public DataResponseMessage<List<UserNewsDTO>> getLikedNewsByUser(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);
        if (user == null) {
            throw new UserNotFoundException();
        }

        List<NewsLike> newsLikes = user.getLikedNews();
        LocalDateTime now = LocalDateTime.now();

        List<UserNewsDTO> likedNews = newsLikes.stream()
                .map(NewsLike::getNews)
                .filter(News::isActive)
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .map(news -> newsConverter.toUserDTO(news, true, true)) // likedByUser = true, viewedByUser = false
                .toList();

        return new DataResponseMessage<>("Kullanıcının beğendiği haberler", true, likedNews);
    }


    @Override
    public ResponseMessage likeNews(Long newsId, String username) throws OutDatedNewsException, NewsIsNotActiveException, NewsNotFoundException, UserNotFoundException {
        User user = userRepository.findByUserNumber(username);
        NewsLike newsLike = new NewsLike();
        LocalDateTime now = LocalDateTime.now();
        News news = newsRepository.findById(newsId).orElseThrow(NewsNotFoundException::new);
        if (!news.isActive()) {
            throw new NewsIsNotActiveException(newsId + " ");
        }

        if (news.getEndDate() == null || news.getEndDate().isAfter(now)) {//tarih formatları uyuşmuyor heralde bu yüzden haber aktif değilmiş gibi dönüyor
            news.setActive(false);
            throw new OutDatedNewsException();
        }
        newsLike.setNews(news);
        newsLike.setUser(user);
        newsLike.setLikedAt(now);
        newsLikeRepository.save(newsLike);
        user.getLikedNews().add(newsLike);
        userRepository.save(user);
        return new ResponseMessage("haber beğenildi", true);

    }

    //beğeni kaldır
    @Override
    public ResponseMessage unlikeNews(Long newsId, String username) throws UserNotFoundException, NewsNotFoundException, NewsIsNotActiveException, OutDatedNewsException {
        User user = userRepository.findByUserNumber(username);
        LocalDateTime now = LocalDateTime.now();
        News news = newsRepository.findById(newsId).orElseThrow(NewsNotFoundException::new);
        if (!news.isActive()) {
            throw new NewsIsNotActiveException(newsId + " ");
        }

        if (news.getEndDate() == null || news.getEndDate().isAfter(now)) {
            news.setActive(false);
            throw new OutDatedNewsException();
        }
        user.getLikedNews().removeIf(newsLike1 -> newsLike1.getNews().equals(news));
        userRepository.save(user);

        return new ResponseMessage("beğeni kaldırıldı", true);
    }


    @Override
    public DataResponseMessage<List<UserNewsDTO>> getPersonalizedNews(String username, PlatformType platform) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);
        if (user == null) {
            return new DataResponseMessage<>("Kullanıcı bulunamadı", false, null);
        }

        // Kullanıcının beğendiği ve görüntülediği haberlerden tip ve öncelik setlerini çıkaralım
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

        // Aktif ve süresi dolmamış haberleri filtrele
        List<News> activeNews = newsRepository.findAll().stream()
                .filter(News::isActive)
                .filter(news -> platform == null || news.getPlatform().equals(platform))
                .filter(news -> news.getEndDate() == null || news.getEndDate().isAfter(now))
                .toList();

        // Kullanıcıya özel skor hesaplayalım
        Set<Long> likedNewsIds = user.getLikedNews().stream()
                .map(like -> like.getNews().getId())
                .collect(Collectors.toSet());

        List<UserNewsDTO> personalizedNews = activeNews.stream()
                .map(news -> {
                    int score = 0;
                    if (likedTypes.contains(news.getType())) score += 3;
                    if (likedPriorities.contains(news.getPriority())) score += 2;
                    if (viewedTypes.contains(news.getType())) score += 2;
                    if (viewedPriorities.contains(news.getPriority())) score += 1;

                    boolean likedByUser = likedNewsIds.contains(news.getId());
                    boolean viewedByUser = newsViewHistoryRepository.existsByUserAndNews(user, news);

                    return new AbstractMap.SimpleEntry<>(newsConverter.toUserDTO(news, likedByUser, viewedByUser), score);
                })
                .filter(entry -> entry.getValue() > 0)  // Sadece ilgisi olan haberler
                .sorted((e1, e2) -> Integer.compare(e2.getValue(), e1.getValue())) // Skora göre azalan
                .map(Map.Entry::getKey)
                .toList();

        return new DataResponseMessage<>("Kişiye özel haberler", true, personalizedNews);
    }


    @Override
    public DataResponseMessage<List<NewsStatistics>> getMonthlyNewsStatistics(String username) throws AdminNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null || !admin.getRoles().contains(Role.ADMIN)) {
            return new DataResponseMessage<>("Yetkisiz erişim", false, null);
        }

        LocalDateTime startOfMonth = LocalDateTime.now().withDayOfMonth(1);
        List<NewsLike> likesThisMonth = newsLikeRepository.findByLikedAtAfter(startOfMonth);
        List<NewsViewHistory> viewsThisMonth = newsViewHistoryRepository.findByViewedAtAfter(startOfMonth);

        List<News> allNews = newsRepository.findAll();

        List<NewsStatistics> stats = allNews.stream()
                .map(news -> newsConverter.toDetailedStatistics(news, likesThisMonth, viewsThisMonth))
                .sorted(Comparator.comparingInt(NewsStatistics::getViewCountThisMonth).reversed())
                .toList();

        return new DataResponseMessage<>("Bu ayın haber istatistikleri", true, stats);
    }


    @Override
    public DataResponseMessage<List<?>> getNewsByCategoryForAdmin(String username, NewsType category, PlatformType platform) {
        List<News> newsList = newsRepository.findByTypeAndActiveTrue(category);

        List<AdminNewsDTO> adminNewsDTOS = newsList.stream()
                .filter(news -> platform == null || news.getPlatform().equals(platform))
                .map(newsConverter::toAdminDTO)
                .toList();

        return new DataResponseMessage<>("Kategoriye göre aktif haberler", true, adminNewsDTOS);
    }

    @Override
    public DataResponseMessage<List<?>> getNewsByCategoryForUser(String username, NewsType category, PlatformType platform) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);
        if (user == null) {
            return new DataResponseMessage<>("Kullanıcı bulunamadı", false, null);
        }

        List<News> newsList = newsRepository.findByTypeAndActiveTrue(category);

        Set<Long> likedNewsIds = user.getLikedNews().stream()
                .map(like -> like.getNews().getId())
                .collect(Collectors.toSet());
        List<UserNewsDTO> userNewsDTOS = newsList.stream()
                .filter(news -> platform == null || news.getPlatform().equals(platform))
                .map(news -> {
                    boolean liked = likedNewsIds.contains(news.getId());
                    boolean viewed = newsViewHistoryRepository.existsByUserAndNews(user, news);
                    return newsConverter.toUserDTO(news, liked, viewed);
                })
                .toList();

        return new DataResponseMessage<>("Kategoriye göre aktif haberler", true, userNewsDTOS);
    }


    @Override
    public DataResponseMessage<List<NewsHistoryDTO>> getNewsViewHistory(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);

        LocalDateTime now = LocalDateTime.now();

        List<NewsHistoryDTO> newsHistoryDTOS = user.getViewedNews().stream()
                .filter(view -> {
                    News news = view.getNews();
                    return news != null &&
                            news.isActive() &&
                            (news.getEndDate() == null || news.getEndDate().isAfter(now));
                })
                .sorted(Comparator.comparing(NewsViewHistory::getViewedAt).reversed())
                .map(newsConverter::toHistoryDTO)
                .toList();

        return new DataResponseMessage<>(
                "Kullanıcının görüntülediği haber geçmişi",
                true,
                newsHistoryDTOS
        );
    }

    @Override
    @Transactional
    public void recordNewsView(String username, Long newsId) throws NewsIsNotActiveException, UserNotFoundException, NewsNotFoundException {
        User user = userRepository.findByUserNumber(username);
        News news = newsRepository.findById(newsId).orElseThrow(NewsNotFoundException::new);
        if (!news.isActive()) {
            throw new NewsIsNotActiveException(newsId + " ");
        }
        NewsViewHistory newsViewHistory = new NewsViewHistory();
        newsViewHistory.setUser(user);
        newsViewHistory.setNews(news);
        newsViewHistory.setViewedAt(LocalDateTime.now());
        newsViewHistoryRepository.save(newsViewHistory);
        user.getViewedNews().add(newsViewHistory);
    }

    @Override
    public DataResponseMessage<List<UserNewsDTO>> getSuggestedNews(String username, PlatformType platformType) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);
        if (user == null) {
            return new DataResponseMessage<>("Kullanıcı bulunamadı", false, null);
        }

        // Kullanıcının beğendiği ve görüntülediği haberleri çek
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

        List<UserNewsDTO> suggested = activeNews.stream()
                .map(news -> {
                    int score = 0;

                    // Beğeni bazlı
                    if (likedTypes.contains(news.getType())) score += 3;
                    if (likedPriorities.contains(news.getPriority())) score += 2;

                    // Görüntülenme bazlı
                    if (viewedTypes.contains(news.getType())) score += 2;
                    if (viewedPriorities.contains(news.getPriority())) score += 1;

                    boolean likedByUser = likedNewsIds.contains(news.getId());
                    boolean viewedByUser = newsViewHistoryRepository.existsByUserAndNews(user, news);

                    UserNewsDTO dto = newsConverter.toUserDTO(news, likedByUser, viewedByUser);
                    return new AbstractMap.SimpleEntry<>(dto, score);
                })
                .sorted((e1, e2) -> Integer.compare(e2.getValue(), e1.getValue()))
                .map(Map.Entry::getKey)
                .toList();

        return new DataResponseMessage<>("Kullanıcıya özel önerilen haberler", true, suggested);
    }

}
