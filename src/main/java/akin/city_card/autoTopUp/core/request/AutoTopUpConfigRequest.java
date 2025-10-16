package akin.city_card.autoTopUp.core.request;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class AutoTopUpConfigRequest {

    @NotNull(message = "Kart ID'si belirtilmeli")
    private Long busCard;

    @NotNull(message = "Eşik değeri belirtilmeli")
    @DecimalMin(value = "0.0", inclusive = false, message = "Eşik değeri 0'dan büyük olmalı")
    @DecimalMax(value = "1000.0", message = "Eşik değeri 1000 TL'yi geçemez")
    private BigDecimal threshold;

    @NotNull(message = "Yüklenecek tutar belirtilmeli")
    @DecimalMin(value = "1.0", message = "Minimum yükleme tutarı 1 TL")
    @DecimalMax(value = "5000.0", message = "Maksimum yükleme tutarı 5000 TL")
    private BigDecimal amount;
}