package akin.city_card.driver.core.converter;

import akin.city_card.driver.core.response.DriverDto;
import akin.city_card.driver.model.Driver;

public interface DriverConverter {
    DriverDto toDto(Driver driver);
}
