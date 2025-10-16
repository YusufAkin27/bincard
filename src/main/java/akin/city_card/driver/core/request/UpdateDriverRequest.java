package akin.city_card.driver.core.request;

import akin.city_card.driver.model.Shift;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UpdateDriverRequest {
    private String address;
    private LocalDate licenseExpiryDate;
    private LocalDate licenseIssueDate;
    private String licenseClass;
    private String licenseNumber;
    private Shift shift;
    private Boolean active;
}
