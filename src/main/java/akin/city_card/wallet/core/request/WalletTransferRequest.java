package akin.city_card.wallet.core.request;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class WalletTransferRequest {

    @NotBlank(message = "Alıcı telefon boş olamaz")
    private String receiverIdentifier;

    @NotBlank(message = "Alıcı Ad Soyad boş olamaz")
    private String receiverNameAndSurname;

    @NotNull(message = "Transfer miktarı zorunludur.")
    @DecimalMin(value = "0.01", inclusive = true, message = "Transfer miktarı en az 0.01 olmalıdır.")
    private BigDecimal amount;

    private String description;
}