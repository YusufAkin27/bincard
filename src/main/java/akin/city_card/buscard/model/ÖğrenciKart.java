package akin.city_card.buscard.model;

import akin.city_card.card_visa.model.CardVisa;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.LocalDate;

@Entity
@Data
@EqualsAndHashCode(callSuper = true)
public class ÖğrenciKart extends BusCard {

    /** Öğrenci belgesi (dosya yolu ya da base64) */
    @Lob
    private String studentDocument;

    /** TC Kimlik numarası */
    private String nationalId;

    /** Doğum tarihi */
    private LocalDate birthDate;

    /** Profil veya vesikalık fotoğraf */
    @Lob
    private String profilePhoto;

    /** Aylık abonman ücreti */
    private Double monthlyFee;

    /** Aylık kullanım limiti (örneğin 200 basım) */
    private Integer maxMonthlyUsages;

    /** O ay yapılan kullanım sayısı */
    private Integer currentMonthUsageCount;

    /** Vize bilgisi (ilişkili varlık) */
    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "visa_id")
    private CardVisa cardVisa;
}
