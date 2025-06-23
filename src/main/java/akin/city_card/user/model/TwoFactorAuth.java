package akin.city_card.user.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "two_factor_auth")
public class TwoFactorAuth {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Kullanıcıya ait 2FA kaydı
    @OneToOne
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    // 2FA aktif mi?
    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    // Doğrulama tipi: EMAIL veya PHONE
    @Enumerated(EnumType.STRING)
    @Column(name = "method", nullable = false)
    private VerificationMethod method;

    private LocalDateTime isCreate;

    // Kod gönderilen hedef (email adresi veya telefon numarası)
    @Column(name = "target", nullable = false)
    private String target;


}
