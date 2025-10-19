package akin.city_card.report.model;

import akin.city_card.security.entity.SecurityUser;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "report_messages")
public class ReportMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Hangi rapora ait
    @ManyToOne(optional = false)
    @JoinColumn(name = "report_id")
    private Report report;

    // Mesaj içeriği
    @Column(nullable = false, columnDefinition = "TEXT")
    private String message;

    // Kim gönderdi (USER/ADMIN)
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private MessageSender sender;

    // Gönderen kullanıcı (eğer USER ise)
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    // Gönderen admin (eğer ADMIN ise)
    @ManyToOne
    @JoinColumn(name = "admin_id")
    private SecurityUser admin;

    // Mesaj ekleri (fotoğraf/dosya)
    @OneToMany(mappedBy = "message", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<MessageAttachment> attachments;

    // Gönderilme zamanı
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime sentAt;

    // Son düzenlenme zamanı
    private LocalDateTime editedAt;

    // Mesaj silinmiş mi
    @Column(nullable = false)
    private boolean deleted = false;

    // Düzenlendi mi
    @Column(nullable = false)
    private boolean edited = false;

    // Admin tarafından okundu mu
    @Column(nullable = false)
    private boolean readByAdmin = false;

    // Kullanıcı tarafından okundu mu
    @Column(nullable = false)
    private boolean readByUser = false;

    @PrePersist
    public void onCreate() {
        // Kendi gönderdiği mesajı okumuş sayılır
        if (sender == MessageSender.ADMIN) {
            this.readByAdmin = true;
        } else {
            this.readByUser = true;
        }
    }
}