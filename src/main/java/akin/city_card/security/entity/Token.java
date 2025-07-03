package akin.city_card.security.entity;


import akin.city_card.security.entity.enums.TokenType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Table(
        name = "token",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "tokenType"})
)
@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 1024)
    private String tokenValue;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private SecurityUser securityUser;

    private boolean isValid = true;

    private LocalDateTime issuedAt;
    private LocalDateTime expiresAt;
    private LocalDateTime lastUsedAt;

    private String ipAddress;
    private String deviceInfo;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenType tokenType;
}
