package akin.city_card.geoIpService;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class GeoLocationData {
    private String city;
    private String region;

    @JsonProperty("country_name")
    private String countryName;

    private String timezone;
    private String org;
}
