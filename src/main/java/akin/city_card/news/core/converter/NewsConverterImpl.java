package akin.city_card.news.core.converter;

import akin.city_card.news.core.request.CreateNewsRequest;
import akin.city_card.news.core.request.UpdateNewsRequest;
import akin.city_card.news.core.response.AdminNewsDTO;
import akin.city_card.news.core.response.NewsHistoryDTO;
import akin.city_card.news.core.response.NewsStatistics;
import akin.city_card.news.core.response.UserNewsDTO;
import akin.city_card.news.model.News;
import akin.city_card.news.model.NewsLike;
import akin.city_card.news.model.NewsViewHistory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

@Component
public class NewsConverterImpl implements NewsConverter {

    @Override
    public UserNewsDTO toNewsDTO(News news, boolean isLiked, boolean isViewed) {
        return UserNewsDTO.builder()
                .id(news.getId())
                .title(news.getTitle())
                .content(news.getContent())
                .image(news.getImage())
                .thumbnail(news.getThumbnail() != null ? news.getThumbnail() : news.getImage() != null ? news.getImage() : "")
                .priority(news.getPriority())
                .type(news.getType())
                .viewCount(news.getViewCount())
                .likeCount(news.getLikes() != null ? news.getLikes().size() : 0)
                .likedByUser(isLiked)
                .viewedByUser(isViewed)
                .build();
    }

    @Override
    public AdminNewsDTO toAdminNewsDTO(News news) {
        return AdminNewsDTO.builder()
                .id(news.getId())
                .title(news.getTitle())
                .content(news.getContent())
                .image(news.getImage())
                .thumbnail(news.getThumbnail() != null ? news.getThumbnail() : news.getImage() != null ? news.getImage() : "")
                .startDate(news.getStartDate())
                .endDate(news.getEndDate())
                .active(news.isActive())
                .platform(news.getPlatform())
                .priority(news.getPriority())
                .type(news.getType())
                .viewCount(news.getViewCount())
                .likeCount(news.getLikes() != null ? news.getLikes().size() : 0)
                .allowFeedback(news.isAllowFeedback())
                .createdAt(news.getCreatedAt())
                .updatedAt(news.getUpdatedAt())
                .build();
    }


    @Override
    public NewsHistoryDTO toHistoryDTO(NewsViewHistory history) {
        return NewsHistoryDTO.builder()
                .newsId(history.getNews().getId())
                .title(history.getNews().getTitle())
                .image(history.getNews().getImage())
                .viewedAt(history.getViewedAt())
                .type(history.getNews().getType())
                .priority(history.getNews().getPriority())
                .build();
    }

    public NewsStatistics toDetailedStatistics(News news, List<NewsLike> likesThisMonth, List<NewsViewHistory> viewsThisMonth) {
        return NewsStatistics.builder()
                .newsId(news.getId())
                .title(news.getTitle())
                .totalViewCount(news.getViewCount())
                .totalLikeCount(news.getLikes() != null ? news.getLikes().size() : 0)
                .viewCountThisMonth((int) viewsThisMonth.stream().filter(view -> view.getNews().getId().equals(news.getId())).count())
                .likeCountThisMonth((int) likesThisMonth.stream().filter(like -> like.getNews().getId().equals(news.getId())).count())
                .firstPublishedDate(news.getCreatedAt())
                .lastUpdatedDate(news.getUpdatedAt())
                .build();
    }

    @Override
    public News fromCreateRequest(CreateNewsRequest request) {
        return News.builder()
                .title(request.getTitle())
                .content(request.getContent())
                .startDate(request.getStartDate())
                .endDate(request.getEndDate())
                .platform(request.getPlatform())
                .priority(request.getPriority())
                .type(request.getType())
                .active(true) // yeni haber aktif başlar
                .viewCount(0)
                .allowFeedback(request.isAllowFeedback())
                .createdAt(LocalDateTime.now())
                .build();
    }

    @Override
    public void updateEntityFromDTO(News news, UpdateNewsRequest dto) {
        if (dto.getTitle() != null && !dto.getTitle().equals(news.getTitle())) {
            news.setTitle(dto.getTitle());
        }

        if (dto.getContent() != null && !dto.getContent().equals(news.getContent())) {
            news.setContent(dto.getContent());
        }


        if (dto.getStartDate() != null && !dto.getStartDate().equals(news.getStartDate())) {
            news.setStartDate(dto.getStartDate());
        }

        if (dto.getEndDate() != null && !dto.getEndDate().equals(news.getEndDate())) {
            news.setEndDate(dto.getEndDate());
        }

        if (dto.getPlatform() != null && dto.getPlatform() != news.getPlatform()) {
            news.setPlatform(dto.getPlatform());
        }

        if (dto.getPriority() != null && dto.getPriority() != news.getPriority()) {
            news.setPriority(dto.getPriority());
        }

        if (dto.getType() != null && dto.getType() != news.getType()) {
            news.setType(dto.getType());
        }

        if (dto.getAllowFeedback() != null && dto.getAllowFeedback() != news.isAllowFeedback()) {
            news.setAllowFeedback(dto.getAllowFeedback());
        }

        if (dto.getActive() != null && dto.getActive() != news.isActive()) {
            news.setActive(dto.getActive());
        }

        news.setUpdatedAt(LocalDateTime.now());
    }

}
