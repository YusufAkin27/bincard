package akin.city_card.report.core.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BulkAssignRequest {
    @NotEmpty(message = "Report ID listesi boş olamaz")
    private List<Long> reportIds;

    @NotNull(message = "Admin username boş olamaz")
    private String adminUsername;
}