package akin.city_card.buscard.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BusCardResponse {
    private String uid;
    private String fullName;
    private String cardType;
    private String cardStatus;
    private Boolean active;
    private BigDecimal balance;
    private boolean lowBalanceNotified;
    private BigDecimal lastTransactionAmount;
    private LocalDate lastTransactionDate;
    private boolean visaCompleted;
    private LocalDate issueDate;
    private LocalDate expiryDate;

    // Abonman Bilgisi
    private boolean abonmanMi;
    private Integer subscriptionLoaded;
    private LocalDate subscriptionEndDate;

    // Meta Veriler
    private Long cardVisaExpiry;
    private Integer txCounter;
    private Long issuedAt;
    private String packageId;
    private String encryptionVersion;
    private String systemId;
    private String issuer;
    private String securityLevel;
}
