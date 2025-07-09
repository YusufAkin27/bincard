package akin.city_card.news.core.response;

import akin.city_card.news.model.NewsPriority;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.user.core.response.Views;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class NewsDTO {

    // Ortak alanlar (User + Admin)
    @JsonView(Views.User.class)
    private Long id;

    @JsonView(Views.User.class)
    private String title;

    @JsonView(Views.User.class)
    private String content;

    @JsonView(Views.User.class)
    private String image;

    @JsonView(Views.User.class)
    private NewsPriority priority;

    @JsonView(Views.User.class)
    private NewsType type;

    @JsonView(Views.User.class)
    private boolean likedByUser;

    @JsonView(Views.User.class)
    private boolean viewedByUser;

    // Sadece Admin'e özel alanlar
    @JsonView(Views.Admin.class)
    private LocalDateTime startDate;

    @JsonView(Views.Admin.class)
    private LocalDateTime endDate;

    @JsonView(Views.Admin.class)
    private boolean active;

    @JsonView(Views.Admin.class)
    private PlatformType platform;

    @JsonView(Views.Admin.class)
    private int viewCount;

    @JsonView(Views.Admin.class)
    private int likeCount;

    @JsonView(Views.Admin.class)
    private boolean allowFeedback;

    @JsonView(Views.Admin.class)
    private LocalDateTime createdAt;

    @JsonView(Views.Admin.class)
    private LocalDateTime updatedAt;
}
