package akin.city_card.driver.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DriverDocumentDto {
    private Long id;
    private String documentName;
    private String documentType;
    private LocalDate expiryDate;
    private String filePath;
}
