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

    private String token;
    private String userNumber;
    private Instant issuedAt;
    private Instant expiresAt;
    private boolean used = false;

}
