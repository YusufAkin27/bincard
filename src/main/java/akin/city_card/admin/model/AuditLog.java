package akin.city_card.admin.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String telephone; // Hangi admin yaptı

    @Enumerated(EnumType.STRING)
    private ActionType action; // LOGIN, DELETE_USER, UPDATE_PROFILE vs.

    private String description; // Örnek: "Kullanıcı X silindi"

    private LocalDateTime timestamp;

    private String ipAddress;
    private String deviceInfo;
}
