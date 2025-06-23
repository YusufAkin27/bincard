package akin.city_card.news.core.request;

import akin.city_card.news.model.NewsPriority;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import jakarta.validation.constraints.Future;
import lombok.Builder;
import lombok.Data;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDateTime;

@Data
@Builder
public class UpdateNewsRequest {

    private Long id; // Güncellenecek haberin ID'si

    private String title;

    private String content;

    private String image;

    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private LocalDateTime startDate;

    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    @Future(message = "Bitiş tarihi gelecekte olmalıdır")
    private LocalDateTime endDate;

    private PlatformType platform;

    private NewsPriority priority;

    private NewsType type;

    private Boolean allowFeedback;

    private Boolean active;
}
