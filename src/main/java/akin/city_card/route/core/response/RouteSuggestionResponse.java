package akin.city_card.route.core.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RouteSuggestionResponse {
    private boolean routeFound;
    private String message;
    private String routeName;
    private String boardAt;
    private String getOffAt;
    private String googleMapUrl;
}
