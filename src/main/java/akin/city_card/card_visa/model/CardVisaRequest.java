package akin.city_card.card_visa.model;

import akin.city_card.admin.model.Admin;
import akin.city_card.buscard.model.BusCard;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CardVisaRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private User applicant; // Başvuru yapan kullanıcı

    @ManyToOne
    private BusCard busCard; // Hangi karta vize istiyor

    private String documentUrl; // Belge URL'si (örn. öğrenci belgesi)
    private LocalDateTime requestDate;
    private String note;

    @Enumerated(EnumType.STRING)
    private RequestStatus status;

    @ManyToOne
    private Admin reviewedBy;

    private LocalDateTime reviewedAt;

    private BigDecimal fee; // Vize ücreti


}
