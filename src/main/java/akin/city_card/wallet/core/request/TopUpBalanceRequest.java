package akin.city_card.wallet.core.request;

import akin.city_card.news.model.PlatformType;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class TopUpBalanceRequest {

    @NotNull(message = "Yüklenecek tutar boş olamaz.")
    @DecimalMin(value = "1.00", message = "En az 1 TL yükleyebilirsiniz.")
    private BigDecimal amount;

    @NotBlank(message = "Kart numarası zorunludur.")
    @Pattern(
            regexp = "^[0-9]{16}$",
            message = "Kart numarası 16 haneli olmalıdır ve sadece rakam içermelidir."
    )
    private String cardNumber;

    //  @NotBlank(message = "Son kullanma tarihi zorunludur.")
    @Pattern(
            regexp = "^(0[1-9]|1[0-2])/([0-9]{2})$",
            message = "Son kullanma tarihi MM/YY formatında olmalıdır (örnek: 09/26)."
    )
    private String cardExpiry;

    //@NotBlank(message = "CVC kodu zorunludur.")
    @Pattern(
            regexp = "^[0-9]{3,4}$",
            message = "CVC kodu 3 veya 4 haneli olmalıdır."
    )
    private String cardCvc;
    @NotNull(message = "Platform tipi zorunludur.")
    private PlatformType platformType;

}
