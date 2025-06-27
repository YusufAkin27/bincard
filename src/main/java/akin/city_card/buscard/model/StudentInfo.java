package akin.city_card.buscard.model;

import akin.city_card.card_visa.model.CardVisa;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Lob;
import jakarta.persistence.OneToOne;
import lombok.Data;

import java.time.LocalDate;

@Embeddable
@Data
public class StudentInfo {

    private String nationalId;
    private LocalDate birthDate;

    @Lob
    private String studentDocument;

    @Lob
    private String profilePhoto;

    @OneToOne(cascade = CascadeType.ALL)
    private CardVisa cardVisa;
}
