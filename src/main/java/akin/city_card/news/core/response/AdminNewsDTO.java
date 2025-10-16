package akin.city_card.news.core.response;

import akin.city_card.news.model.NewsPriority;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class AdminNewsDTO {

    private Long id;

    private String title;

    private String content;

    private String image;


    private String thumbnail;

    private NewsPriority priority;

    private NewsType type;

    private boolean likedByUser;

    private boolean viewedByUser;


    private int viewCount;

    private int likeCount;
    private LocalDateTime startDate;

    private LocalDateTime endDate;

    private boolean active;

    private PlatformType platform;
    private boolean allowFeedback;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
}

