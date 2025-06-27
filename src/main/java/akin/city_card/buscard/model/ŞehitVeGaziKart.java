package akin.city_card.buscard.model;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Lob;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.LocalDate;

@Entity
@Data
@EqualsAndHashCode(callSuper = true)
public class ŞehitVeGaziKart extends BusCard {

    public enum DocumentType {
        MARTYR_RELATIVE_CERTIFICATE,
        VETERAN_ID,
        OTHER
    }

    /** TC Kimlik numarası */
    private String nationalId;

    /** Doğum tarihi */
    private LocalDate birthDate;

    /** Belge tipi */
    @Enumerated(EnumType.STRING)
    private DocumentType documentType;

    /** İlgili belge (gazi kimliği, şehit belgesi vs.) */
    @Lob
    private String officialDocument;

    /** Profil fotoğrafı */
    @Lob
    private String profilePhoto;
}
