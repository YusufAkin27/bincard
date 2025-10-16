package akin.city_card.notification.model;

import akin.city_card.user.model.User;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Data
@AllArgsConstructor
@Builder
@NoArgsConstructor
public class Notification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Bildirimin kime ait olduğu
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonBackReference
    private User user;

    // Başlık (isteğe bağlı)
    @Column(length = 100)
    private String title;

    // Mesaj içeriği
    @Column(length = 500)
    private String message;

    // Bildirim tipi (örneğin: INFO, ALERT, SUCCESS)
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private NotificationType type;

    // Oluşturulma zamanı
    @CreationTimestamp
    private LocalDateTime sentAt;

    // Okundu bilgisi
    private boolean isRead = false;

    // Ne zaman okundu
    private LocalDateTime readAt;

    // İlgili işlem ya da yönlendirme (opsiyonel)
    @Column(length = 255)
    private String targetUrl;

    // Soft delete için (isteğe bağlı)
    private boolean deleted = false;
}
