package akin.city_card.news.model;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class News {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String thumbnail;
    @Column(nullable = false, length = 150)
    private String title;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String content;

    private String image;

    @Column(nullable = false)
    private LocalDateTime startDate; // Ne zaman yayınlansın?

    private LocalDateTime endDate;   // Ne zaman yayından kalksın?

    @Column(nullable = false)
    private boolean active = true;   // Manuel devre dışı bırakma için

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PlatformType platform;   // WEB, MOBILE, ALL

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private NewsPriority priority = NewsPriority.NORMAL; // LOW, NORMAL, HIGH

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private NewsType type = NewsType.BILGILENDIRME; // BİLGİ, DUYURU, BAKIM, KAMPANYA vs.

    private int viewCount = 0; // Kaç kişi okudu

    private boolean allowFeedback = true; // Beğeni vs. açık mı?

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // Beğeniler
    @OneToMany(mappedBy = "news", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<NewsLike> likes;
}
