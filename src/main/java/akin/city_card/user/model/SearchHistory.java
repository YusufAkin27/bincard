package akin.city_card.user.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SearchHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Kullanıcıyla ilişki
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Arama metni (örneğin durak ismi, rota, kart vs.)
    @Column(nullable = false, length = 255)
    private String query;

    // Arama zamanı
    private LocalDateTime searchedAt;

    // Arama türü isteğe bağlı (örneğin ROUTE, STATION, CARD vs.)
    private String searchType;
}
