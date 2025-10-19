package akin.city_card.report.model;

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
@NoArgsConstructor
@Builder
@Table(name = "message_attachments")
public class MessageAttachment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Hangi mesaja ait
    @ManyToOne(optional = false)
    @JoinColumn(name = "message_id")
    private ReportMessage message;

    // Dosya URL'i
    @Column(nullable = false, length = 500)
    private String fileUrl;

    // Dosya tipi (IMAGE, VIDEO, DOCUMENT)
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AttachmentType type;

    // Dosya adı
    @Column(length = 255)
    private String fileName;

    // Dosya boyutu (byte)
    private Long fileSize;

    // Yüklenme zamanı
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime uploadedAt;
}
