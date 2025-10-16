package akin.city_card.report.core.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SendMessageRequest {
    @NotNull(message = "Report ID boş olamaz")
    private Long reportId;

    @NotBlank(message = "Mesaj boş olamaz")
    @Size(min = 1, max = 1000, message = "Mesaj 1-1000 karakter arasında olmalıdır")
    private String message;
}
