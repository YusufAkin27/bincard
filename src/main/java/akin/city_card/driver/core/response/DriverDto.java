package akin.city_card.driver.core.response;

import akin.city_card.driver.model.Shift;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DriverDto {
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String nationalId;
    private LocalDate dateOfBirth;
    private LocalDate employmentDate;
    private LocalDate licenseIssueDate;
    private String licenseClass;
    private String licenseNumber;
    private LocalDate licenseExpiryDate;
    private String address;
    private Shift shift;
    private Long totalDrivingHours;
    private Double totalDistanceDriven;
    private Long totalPassengersTransported;
    private BigDecimal totalEarnings;
    private Double averageRating;
    private Boolean active;
    private LocalDate healthCertificateExpiry;
}

