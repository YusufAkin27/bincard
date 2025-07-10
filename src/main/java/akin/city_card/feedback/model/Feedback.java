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

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
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
}
