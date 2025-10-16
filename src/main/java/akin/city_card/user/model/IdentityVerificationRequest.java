package akin.city_card.user.model;

import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "identity_verification_requests")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IdentityVerificationRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Kimlik bilgisi bağlantısı
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "identity_info_id", nullable = false)
    private UserIdentityInfo identityInfo;

    // Kim tarafından başvuru yapıldı (genelde kullanıcı)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "requested_by_user_id", nullable = false)
    private SecurityUser requestedBy;

    @Column(nullable = false)
    private LocalDateTime requestedAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RequestStatus status;

    @Column(length = 255)
    private String adminNote;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reviewed_by_user_id")
    private SecurityUser reviewedBy;

    private LocalDateTime reviewedAt;


}
