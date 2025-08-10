package akin.city_card.buscard.core.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class UserFavoriteCardResponse {
    private Long id;
    private String nickname;
    private LocalDateTime created;
    private BusCardResponse card;
}