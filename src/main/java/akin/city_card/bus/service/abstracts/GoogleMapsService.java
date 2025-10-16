package akin.city_card.bus.service.abstracts;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoogleMapsService {

    @Value("${google.maps.api.key}")
    private String apiKey;

    // Directions API URL (sürüş tarifleri için)
    @Value("${google.maps.api.directions.url:https://maps.googleapis.com/maps/api/directions/json}")
    private String directionsApiUrl;

    // Geocoding API URL (adres -> koordinat için)
    @Value("${google.maps.api.geocode.url:https://maps.googleapis.com/maps/api/geocode/json}")
    private String geocodeApiUrl;

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();


    public Integer getEstimatedTimeInMinutes(double originLat, double originLng, double destLat, double destLng) {
        String url = UriComponentsBuilder.fromHttpUrl(directionsApiUrl)
                .queryParam("origin", originLat + "," + originLng)
                .queryParam("destination", destLat + "," + destLng)
                .queryParam("key", apiKey)
                .toUriString();

        try {
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            JsonNode root = objectMapper.readTree(response.getBody());

            JsonNode duration = root.path("routes").get(0)
                    .path("legs").get(0)
                    .path("duration")
                    .path("value"); // saniye cinsinden

            return duration.asInt() / 60; // dakika
        } catch (Exception e) {
            log.error("ETA hesaplanamadı", e);
            return null;
        }
    }


    public boolean isNear(double lat1, double lng1, double lat2, double lng2, double maxDistanceMeters) {
        double earthRadius = 6371000;
        double dLat = Math.toRadians(lat2 - lat1);
        double dLng = Math.toRadians(lng2 - lng1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                + Math.sin(dLng / 2) * Math.sin(dLng / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        double distance = earthRadius * c;
        return distance <= maxDistanceMeters;
    }


    public LatLng getCoordinatesFromAddress(String address) {
        try {
            String url = UriComponentsBuilder.fromHttpUrl(geocodeApiUrl)
                    .queryParam("address", address)
                    .queryParam("key", apiKey)
                    .build()
                    .toUriString();

            String response = restTemplate.getForObject(url, String.class);
            JsonNode root = objectMapper.readTree(response);

            String status = root.path("status").asText();
            if (!"OK".equals(status)) {
                log.warn("Google Geocoding API returned status: {}", status);
                return null;
            }

            JsonNode locationNode = root.path("results").get(0).path("geometry").path("location");
            double lat = locationNode.path("lat").asDouble();
            double lng = locationNode.path("lng").asDouble();

            return new LatLng(lat, lng);

        } catch (Exception e) {
            log.error("Error during Google Maps Geocoding API call", e);
            return null;
        }
    }

    public record LatLng(double lat, double lng) {
    }


    @Data
    static class Route {
        private List<Leg> legs;
        private String summary;
    }

    @Data
    static class Leg {
        private Duration duration;
        private Duration duration_in_traffic;
        private Distance distance;
        private String start_address;
        private String end_address;
    }

    @Data
    static class Duration {
        private String text;
        private int value; // saniye cinsinden
    }

    @Data
    static class Distance {
        private String text;
        private int value; // metre cinsinden
    }


}
