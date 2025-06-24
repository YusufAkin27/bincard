package akin.city_card.news.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NewsStatistics {

    private Long newsId;

    private String title;

    private int totalViewCount;
    private int totalLikeCount;

    private int viewCountThisMonth;
    private int likeCountThisMonth;

    private LocalDateTime firstPublishedDate;
    private LocalDateTime lastUpdatedDate;
}
