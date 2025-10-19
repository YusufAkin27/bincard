package akin.city_card.station.core.request;

import akin.city_card.station.model.StationType;
import akin.city_card.validations.ValidLatitude;
import akin.city_card.validations.ValidLongitude;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class CreateStationRequest {

    @NotBlank
    private String name;

    @NotNull
    @ValidLatitude
    private Double latitude;

    @NotNull
    @ValidLongitude
    private Double longitude;

    @NotNull
    private StationType type;

    @NotBlank
    private String city;

    @NotBlank
    private String district;

    @NotBlank
    private String street;

    private String postalCode;
}
