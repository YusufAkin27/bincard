package akin.city_card.feedback.core.request;

import akin.city_card.feedback.model.FeedbackType;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;

@Data
public class FeedbackRequest {

    private String subject;              // Geri bildirim başlığı
    private String message;              // Kullanıcı mesajı
    private FeedbackType type;           // ÖNERİ / ŞİKAYET / TEKNİK_SORUN / DİĞER
    private String source;               // Kaynak: web / mobil / kiosk vs.
    private MultipartFile photo;
}
