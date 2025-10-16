package akin.city_card.admin.model;

import akin.city_card.superadmin.model.SuperAdmin;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminApprovalRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Onay bekleyen admin
    @OneToOne
    @JoinColumn(name = "admin_id", nullable = false)
    private Admin admin;

    // Onaylayan superadmin (null olabilir çünkü henüz onaylanmamış olabilir)
    @ManyToOne
    @JoinColumn(name = "approved_by_id")
    private SuperAdmin approvedBy;

    // Onay zamanı
    private LocalDateTime approvedAt;

    // Talep oluşturulma zamanı
    @CreationTimestamp
    private LocalDateTime requestedAt;

    private LocalDateTime updateAt;
    private LocalDateTime createdAt;

    // Onay durumu
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ApprovalStatus status;

    // Açıklama (isteğe bağlı)
    private String note;
}
