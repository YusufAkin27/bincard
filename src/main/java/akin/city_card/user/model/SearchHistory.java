package akin.city_card.user.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "search_history")
public class SearchHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Kullanıcıyla ilişki (fetch lazy tercih edilir)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Arama metni (örneğin durak ismi, rota, kart vs.)
    @Column(nullable = false, length = 255)
    private String query;

    // Arama zamanı
    @Column(nullable = false)
    @CreationTimestamp
    private LocalDateTime searchedAt;

    // Aktiflik durumu (örn: arama hala geçerli mi, iptal edildi mi)
    @Column(nullable = false)
    private boolean active;

    // Silinmiş (soft delete) işareti
    @Column(nullable = false)
    private boolean deleted;

    // Silinme zamanı
    private LocalDateTime deletedAt;

    // Arama türü enum olarak tanımlandı
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private SearchType searchType;

    // Kayıt oluşturulma ve güncellenme zamanları (isteğe bağlı)
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;


}
