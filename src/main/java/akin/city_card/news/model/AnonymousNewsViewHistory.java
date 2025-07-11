package akin.city_card.news.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "anonymous_news_view_history")
public class AnonymousNewsViewHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String clientIp;

    @ManyToOne(optional = false)
    @JoinColumn(name = "news_id")
    private News news;

    @Column(nullable = false)
    private LocalDateTime viewedAt;

    @Column(nullable = false)
    private String userAgent;

    @Column(nullable = false)
    private String sessionId;

    @PrePersist
    protected void onCreate() {
        if (viewedAt == null) {
            viewedAt = LocalDateTime.now();
        }
    }
}