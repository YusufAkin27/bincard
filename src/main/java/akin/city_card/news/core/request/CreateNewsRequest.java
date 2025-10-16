package akin.city_card.news.core.request;

import akin.city_card.news.model.NewsPriority;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;

@Data
@Builder
public class CreateNewsRequest {

    @NotBlank(message = "Haber başlığı boş olamaz")
    private String title;

    @NotBlank(message = "Haber içeriği boş olamaz")
    private String content;

    @NotBlank(message = "Haber kapak boş olamaz")
    private MultipartFile thumbnail;

    private MultipartFile image; // opsiyonel: URL ya da base64 image olabilir

    @NotNull(message = "Başlangıç tarihi zorunludur")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private LocalDateTime startDate;

    @Future(message = "Bitiş tarihi gelecekte olmalıdır")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private LocalDateTime endDate;

    @NotNull(message = "Platform tipi zorunludur")
    private PlatformType platform;

    @NotNull(message = "Öncelik seviyesi zorunludur")
    private NewsPriority priority;

    @NotNull(message = "Haber türü zorunludur")
    private NewsType type;

    private boolean allowFeedback;
}
