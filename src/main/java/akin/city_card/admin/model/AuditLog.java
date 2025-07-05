package akin.city_card.admin.model;

import akin.city_card.admin.model.ActionType;
import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "audit_logs")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // İşlemi yapan kullanıcı (Admin veya User olabilir)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private SecurityUser user;

    @Enumerated(EnumType.STRING)
    private ActionType action;

    // Açıklama: “Karta 50₺ yüklendi”, “Profil güncellendi” vs.
    @Column(length = 1000)
    private String description;

    private LocalDateTime timestamp;

    // IP ve cihaz bilgisi
    @Embedded
    private DeviceInfo deviceInfo;

    // 🧾 Hedef entite bilgisi
    private UUID targetEntityId;

    private String targetEntityType; // örn: "BUS_CARD", "WALLET", "USER"

    // 💸 Eğer işlem parasal ya da sayısal bir değer içeriyorsa
    private Double amount;

    // 🧠 Ek açıklama veya JSON/CSV vs. gibi string metadata
    @Column(length = 2000)
    private String metadata;
}
