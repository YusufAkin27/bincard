package akin.city_card.news.core.response;

import akin.city_card.news.model.NewsPriority;
import akin.city_card.news.model.NewsType;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserNewsDTO {


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
}
