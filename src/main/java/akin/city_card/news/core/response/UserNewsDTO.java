package akin.city_card.news.core.response;

import akin.city_card.news.model.NewsPriority;
import akin.city_card.news.model.NewsType;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserNewsDTO {
    private Long id;
    private String title;
    private String content;
    private String image;
    private boolean likedByUser;
    private boolean viewedByUser;
    private NewsPriority priority;
    private NewsType type;
}
