package akin.city_card.buscard.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Lob;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.LocalDate;

@Entity
@Data
@EqualsAndHashCode(callSuper = true)
public class EngelliKart extends BusCard {

    /** Engellilik oranı (%) */
    private Double disabilityRate;

    /** Refakatçi hakkı var mı? */
    private Boolean hasCompanionAccess;

    /** Engelli belgesi (base64 ya da dosya yolu) */
    @Lob
    private String disabilityDocument;

    /** TC Kimlik numarası */
    private String nationalId;

    /** Doğum tarihi */
    private LocalDate birthDate;

    /** Profil veya vesikalık fotoğraf */
    @Lob
    private String profilePhoto;
}
