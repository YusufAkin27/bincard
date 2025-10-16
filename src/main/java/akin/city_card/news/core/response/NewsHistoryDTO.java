package akin.city_card.news.core.response;

import akin.city_card.news.model.NewsPriority;
import akin.city_card.news.model.NewsType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NewsHistoryDTO {

    private Long newsId;

    private String title;

    private String image;

    private LocalDateTime viewedAt;

    private NewsType type;

    private NewsPriority priority;
}
