package akin.city_card.feedback.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Feedback {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // User artık nullable - anonim feedback için
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false, length = 100)
    private String subject;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String message;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FeedbackType type; // Öneri, Şikayet, Teknik Hata, vs.

    @Column(nullable = false)
    private LocalDateTime submittedAt;

    private LocalDateTime updatedAt;

    @Column(length = 100)
    private String source; // mobil/web/terminal vb.

    @Column(length = 500)
    private String photoUrl;

    // Anonim kullanıcı için iletişim bilgileri
    @Column(length = 100)
    private String contactEmail;

    @Column(length = 50)
    private String contactName;

    @Column(length = 20)
    private String contactPhone;

    // Anonim feedback olup olmadığını kontrol etmek için
    @Column(nullable = false)
    @Builder.Default
    private Boolean isAnonymous = false;

    // Helper method - feedback'in anonim olup olmadığını kontrol eder
    public boolean isAnonymous() {
        return this.user == null || Boolean.TRUE.equals(this.isAnonymous);
    }

    // Helper method - contact email'i getirir (user'dan veya direkt contact'tan)
    public String getEffectiveContactEmail() {
        if (isAnonymous()) {
            return this.contactEmail;
        }
        return this.user != null && this.user.getProfileInfo() != null
                ? this.user.getProfileInfo().getEmail()
                : this.contactEmail;
    }

    // Helper method - contact name'i getirir
    public String getEffectiveContactName() {
        if (isAnonymous()) {
            return this.contactName;
        }
        return this.user != null && this.user.getProfileInfo() != null
                ? this.user.getProfileInfo().getName() + " " + this.user.getProfileInfo().getSurname()
                : this.contactName;
    }
}