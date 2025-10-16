package akin.city_card.buscard.core.request;

import akin.city_card.buscard.model.CardStatus;
import akin.city_card.buscard.model.CardType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class RegisterCardRequest {

    private String uid;
    private String fullName;
    private CardStatus status;
    private CardType kartTipi;               // Kart tipi: ÖRNEK: STUDENT, SUBSCRIBER, NORMAL
    private boolean abonmanMi;               // Kart abonman kartı mı? (true/false)
    private Integer abonmanBinisSayisi;      // Abonman kart ise toplam biniş hakkı
    private Long abonmanBitisTarihi;         // Abonman kartın süresi ne zaman doluyor (Unix epoch)
    private Long kartVizeBitisTarihi;        // Kartın vizesi ne zaman doluyor (Unix epoch)
    private BigDecimal bakiye;               // Kart bakiyesi (TL veya kuruş)
    private BigDecimal sonIslemTutari;       // Kart üzerinde yapılan son işlem tutarı
    private Long sonIslemTarihi;             // Son işlem zamanı (Unix epoch)
    private boolean aktif;                    // Kart aktif mi? (true/false)
    private boolean vizeTamamlandi;          // Kartın vizesi tamamlandı mı? (true/false)
}
