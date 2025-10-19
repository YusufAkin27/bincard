package akin.city_card.feedback.core.request;

import akin.city_card.feedback.model.FeedbackType;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class AnonymousFeedbackRequest {

    @NotBlank(message = "Konu alanı boş olamaz")
    @Size(max = 100, message = "Konu en fazla 100 karakter olabilir")
    private String subject;

    @NotBlank(message = "Mesaj alanı boş olamaz")
    @Size(max = 1000, message = "Mesaj en fazla 1000 karakter olabilir")
    private String message;

    @NotNull(message = "Geri bildirim türü belirtilmelidir")
    private FeedbackType type;

    private String source; // mobil/web/terminal

    // Opsiyonel email - eğer kullanıcı geri dönüş istiyorsa
    @Email(message = "Geçerli bir email adresi giriniz")
    private String contactEmail;

    // Opsiyonel isim - kişiselleştirme için
    @Size(max = 50, message = "İsim en fazla 50 karakter olabilir")
    private String contactName;

    // Opsiyonel telefon
    @Size(max = 20, message = "Telefon numarası en fazla 20 karakter olabilir")
    private String contactPhone;

    // Opsiyonel görsel
    private MultipartFile photo;
}