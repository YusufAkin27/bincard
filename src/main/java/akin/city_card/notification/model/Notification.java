package akin.city_card.notification.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class Notification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Bildirimin kime ait olduğu
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
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
