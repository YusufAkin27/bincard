package akin.city_card.feedback.core.request;

import akin.city_card.feedback.model.FeedbackType;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class FeedbackRequest {

    private String subject;              // Geri bildirim başlığı
    private String message;              // Kullanıcı mesajı
    private FeedbackType type;           // ÖNERİ / ŞİKAYET / TEKNİK_SORUN / DİĞER
    private String source;               // Kaynak: web / mobil / kiosk vs.
    private MultipartFile photo;
}
