package akin.city_card.user.core.response;

import akin.city_card.user.model.RequestStatus;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class IdentityVerificationRequestDTO {

    private Long id;

    // Kimlik bilgilerini temsil eden DTO
    private UserIdentityInfoDTO identityInfo;

    // Başvuruyu yapan kullanıcının telefon numarası
    private String requestedByPhone;

    // Başvurunun yapıldığı zaman
    private LocalDateTime requestedAt;

    // Başvurunun mevcut durumu (PENDING, APPROVED, REJECTED)
    private RequestStatus status;

    // Admin notu (isteğe bağlı)
    private String adminNote;

    // Başvuruyu değerlendiren yöneticinin telefon numarası
    private String reviewedByPhone;

    // Değerlendirme zamanı
    private LocalDateTime reviewedAt;
}
