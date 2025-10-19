package akin.city_card.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_audit_log",
        indexes = {
                @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
                @Index(name = "idx_audit_username", columnList = "username"),
                @Index(name = "idx_audit_ip", columnList = "ipAddress"),
                @Index(name = "idx_audit_event_type", columnList = "eventType"),
                @Index(name = "idx_audit_success", columnList = "success")
        })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SecurityEventType eventType;

    @Column(length = 100)
    private String username;

    @Column(length = 45) // IPv6 için yeterli
    private String ipAddress;

    @Column(length = 500)
    private String userAgent;

    @Column(length = 200)
    private String requestUri;

    @Column(length = 10)
    private String httpMethod;

    @Column(length = 1000)
    private String eventDetails;

    @CreationTimestamp
    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Builder.Default
    private boolean success = true;

    @Column(length = 20)
    @Builder.Default
    private String severity = "MEDIUM";

    // Geographical information
    private String country;
    private String city;
    private String region;

    // Session information
    private String sessionId;

    // Risk score (0-100)
    @Builder.Default
    private Integer riskScore = 0;

    // Additional metadata (JSON format)
    @Column(length = 2000)
    private String metadata;
}