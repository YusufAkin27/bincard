package akin.city_card.driver.core.converter;

import akin.city_card.driver.core.response.DriverDto;
import akin.city_card.driver.model.Driver;
import org.springframework.stereotype.Component;

@Component
public class DriverConverterImpl implements DriverConverter {

    @Override
    public DriverDto toDto(Driver driver) {
        if (driver == null) {
            return null;
        }

        return DriverDto.builder()
                .id(driver.getId())
                .firstName(driver.getProfileInfo().getName())
                .lastName(driver.getProfileInfo().getSurname())
                .email(driver.getProfileInfo().getEmail())
                .nationalId(driver.getNationalId())
                .dateOfBirth(driver.getDateOfBirth())
                .employmentDate(driver.getEmploymentDate())
                .licenseIssueDate(driver.getLicenseIssueDate())
                .licenseClass(driver.getLicenseClass())
                .licenseNumber(driver.getLicenseNumber())
                .licenseExpiryDate(driver.getLicenseExpiryDate())
                .address(driver.getAddress())
                .shift(driver.getShift())
                .totalDrivingHours(driver.getTotalDrivingHours())
                .totalDistanceDriven(driver.getTotalDistanceDriven())
                .totalPassengersTransported(driver.getTotalPassengersTransported())
                .totalEarnings(driver.getTotalEarnings())
                .averageRating(driver.getAverageRating())
                .active(driver.getActive())
                .healthCertificateExpiry(driver.getHealthCertificateExpiry())
                .build();
    }
}