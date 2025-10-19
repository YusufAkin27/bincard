package akin.city_card.buscard.core.response;

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
public class BusCardDTO {
    private Long id;
    private String cardNumber;
    private String fullName;
    private CardType type;
    private CardStatus status;
    private BigDecimal balance;
    private boolean active;
    private LocalDate issueDate;
    private LocalDate expiryDate;
    private boolean visaCompleted;
    private BigDecimal lastTransactionAmount;
    private LocalDate lastTransactionDate;
}
