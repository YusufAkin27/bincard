package akin.city_card.buscard.core.response;

import akin.city_card.buscard.model.CardStatus;
import akin.city_card.buscard.model.CardType;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;

@Data
public class FavoriteBusCardDTO {
    private Long id;
    private String cardNumber;
    private String fullName;
    private CardType type;
    private BigDecimal balance;
    private CardStatus status;
    private boolean active;
    private LocalDate issueDate;
    private LocalDate expiryDate;
    private Long userId;
    private String nickname;
}
