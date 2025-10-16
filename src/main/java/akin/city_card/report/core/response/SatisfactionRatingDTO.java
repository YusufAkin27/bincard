package akin.city_card.report.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SatisfactionRatingDTO {

    private Integer rating;
    private String comment;
    private LocalDateTime ratedAt;
    private boolean isRated;
}