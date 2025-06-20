package akin.city_card.card_visa.model;

import akin.city_card.admin.model.Admin;
import akin.city_card.buscard.model.BusCard;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CardVisa {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDate visaStartDate;
    private LocalDate visaEndDate;

    @Enumerated(EnumType.STRING)
    private VisaStatus status;

    private String note;

    @ManyToOne
    private Admin verifiedBy;

    @ManyToOne
    @JoinColumn(name = "bus_card_id")
    private BusCard busCard;

    @OneToOne
    private CardVisaRequest requestReference; // Bu vize hangi başvurudan doğdu

    public boolean isActive() {
        LocalDate today = LocalDate.now();
        return status == VisaStatus.VALID &&
                !today.isBefore(visaStartDate) &&
                !today.isAfter(visaEndDate);
    }


}

