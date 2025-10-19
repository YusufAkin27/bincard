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
    private Long kartVizeBitisTarihi;        // Kartın vizesi ne zaman doluyor (Unix epoch)
    private BigDecimal bakiye;               // Kart bakiyesi (TL veya kuruş)
}
