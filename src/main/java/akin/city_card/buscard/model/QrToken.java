package akin.city_card.buscard.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Table(name = "qr_tokens")
@Data
public class QrToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 2048, nullable = false)
    private String token;

    @Column(length = 255)
    private String userNumber;
    private Instant issuedAt;
    private Instant expiresAt;
    private boolean used = false;

}
