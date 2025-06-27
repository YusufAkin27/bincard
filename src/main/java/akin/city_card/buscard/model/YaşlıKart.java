package akin.city_card.buscard.model;

import jakarta.persistence.Entity;


import jakarta.persistence.Entity;
import jakarta.persistence.Lob;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.LocalDate;

@Entity
@Data
@EqualsAndHashCode(callSuper = true)
public class YaşlıKart extends BusCard {

    /** TC Kimlik numarası */
    private String nationalId;

    /** Doğum tarihi */
    private LocalDate birthDate;

    /** 65 yaş üstü olduğunu gösteren belge (örnek: kimlik fotoğrafı) */
    @Lob
    private String identityDocument;

    /** Profil fotoğrafı (isteğe bağlı) */
    @Lob
    private String profilePhoto;
}
