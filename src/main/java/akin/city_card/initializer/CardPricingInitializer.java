package akin.city_card.initializer;

import akin.city_card.buscard.model.CardPricing;
import akin.city_card.buscard.model.CardType;
import akin.city_card.buscard.repository.CardPricingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Map;


@Component
@RequiredArgsConstructor
@Order(15)
@Slf4j
public class CardPricingInitializer implements CommandLineRunner {

    private final CardPricingRepository cardPricingRepository;

    @Override
    public void run(String... args) throws Exception {

        if (cardPricingRepository.count() > 0) {
            log.info("CardPricing verisi zaten mevcut.");
            return;
        }

        // Kart tipleri ve fiyatları
        Map<CardType, BigDecimal> cardPrices = Map.of(
                CardType.TAM, BigDecimal.valueOf(15),
                CardType.ÖĞRENCİ, BigDecimal.valueOf(10),
                CardType.ÖĞRETMEN, BigDecimal.valueOf(12),
                CardType.YAŞLI, BigDecimal.valueOf(5),
                CardType.ENGELLİ, BigDecimal.valueOf(5),
                CardType.TAM_AKTARMA, BigDecimal.valueOf(7),
                CardType.ÖĞRENCİ_AKTARMA, BigDecimal.valueOf(5),
                CardType.QR_ÖDEME,BigDecimal.valueOf(20)
        );

        cardPrices.forEach((type, price) -> {
            CardPricing cardPricing = CardPricing.builder()
                    .cardType(type)
                    .price(price)
                    .build();
            cardPricingRepository.save(cardPricing);
            log.info("{} tipi için fiyat {} TL olarak eklendi.", type, price);
        });

        log.info("Tüm kart tipleri için fiyatlandırma oluşturuldu.");
    }
}
