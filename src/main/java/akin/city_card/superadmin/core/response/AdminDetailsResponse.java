package akin.city_card.superadmin.core.response;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;

@Data
public class AdminDetailsResponse {
    private Long id;                      // Admin ID
    private String name;                  // Ad Soyad
    private String email;                 // E-posta adresi
    private String telephone;             // Telefon numarası
    private String status;                // Hesap durumu (ACTIVE, SUSPENDED, vb.)
    private List<String> role;                  // Rol (ADMIN, SUPER_ADMIN, vb.)

    private boolean superAdminApproved;   // Üst yönetici onay durumu
    private LocalDateTime approvedAt;     // Onay tarihi
    private LocalDateTime registeredAt;   // Kayıt tarihi

    private String lastLoginIp;           // Son giriş yapılan IP adresi
    private LocalDateTime lastLoginAt;    // Son giriş tarihi
    private int totalLogins;              // Toplam giriş sayısı

    private String department;            // Bağlı olduğu departman (örn: Ulaşım, Finans, Teknik)
    private String createdBy;             // Admini oluşturan kişi (SuperAdmin adı)
    private String updatedBy;             // Son düzenlemeyi yapan kişi
    private LocalDateTime updatedAt;      // Son düzenleme tarihi

    private boolean emailVerified;        // E-posta doğrulandı mı?
    private boolean phoneVerified;        // Telefon doğrulandı mı?

    private String notes;                 // İç notlar (super admin tarafından eklenebilir)
}
