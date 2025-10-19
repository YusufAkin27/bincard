package akin.city_card.report.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AdminReportResponseDTO {
    private Long id;
    private String responseMessage;
    private SimpleUserDTO user;
    private SimpleAdminDTO admin;
    private List<AdminReportResponseDTO> replies;
    private LocalDateTime respondedAt;
}
