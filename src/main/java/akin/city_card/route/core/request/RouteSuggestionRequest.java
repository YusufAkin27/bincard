package akin.city_card.route.core.request;

import lombok.Data;

@Data
public class RouteSuggestionRequest {
    private double userLat;
    private double userLng;
    private String destinationAddress; // Örnek: "Devlet Hastanesi"
}
