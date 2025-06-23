package akin.city_card.report.model;

import akin.city_card.admin.model.Admin;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "report_responses")
public class ReportResponse {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Rapor (en üst bağlantı her zaman olmalı)
    @ManyToOne(optional = false)
    @JoinColumn(name = "report_id")
    private Report report;

    // Admin yanıtladıysa
    @ManyToOne
    @JoinColumn(name = "admin_id")
    private Admin admin;

    // Kullanıcı yanıtladıysa
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    // Yanıt içeriği
    @Column(nullable = false, columnDefinition = "TEXT")
    private String responseMessage;

    // Hangi cevaba cevap veriliyor (nullable = üst düzey yorum)
    @ManyToOne
    @JoinColumn(name = "parent_id")
    private ReportResponse parent;

    // Alt cevaplar
    @OneToMany(mappedBy = "parent", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ReportResponse> replies;

    // Oluşturulma zamanı
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime respondedAt;
}
/* örnek
{
  "id": 1,
  "responseMessage": "Merhaba, şikayetiniz değerlendiriliyor.",
  "admin": {
    "id": 5,
    "name": "Yönetici Ali"
  },
  "replies": [
    {
      "id": 2,
      "responseMessage": "Teşekkür ederim bilgi için.",
      "user": {
        "id": 12,
        "name": "Ahmet"
      },
      "replies": []
    }
  ]
}

 */