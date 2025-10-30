package akin.city_card.buscard.core.request;

import akin.city_card.buscard.model.CardStatus;
import akin.city_card.buscard.model.CardType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class RegisterCardRequest {

    private String uid;
    private String fullName;
    private CardStatus status;
    private CardType kartTipi;               // Kart tipi: ÖRNEK: STUDENT, SUBSCRIBER, NORMAL
    private BigDecimal bakiye;               // Kart bakiyesi (TL veya kuruş)
}
