package akin.city_card.report.core.request;

import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportPhoto;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder

public class AddReportRequest {

    @NotNull(message = "Kategori boş olamaz")
    private ReportCategory category;
    @NotNull(message = "Mesaj boş olamaz")
    private String message;
    private List<ReportPhoto> photos;
}
