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


@Component
@RequiredArgsConstructor
@Order(15)
@Slf4j
public class CardPricingInitializer implements CommandLineRunner {
    private final CardPricingRepository cardPricingRepository;

    @Override
    public void run(String... args) throws Exception {
        if (cardPricingRepository.count() == 0) {
            CardPricing cardPricing = new CardPricing();
            cardPricing.setCardType(CardType.TAM);
            cardPricing.setPrice(BigDecimal.valueOf(15));
            cardPricing.setCreatedAt(LocalDateTime.now());
            cardPricing.setUpdatedAt(LocalDateTime.now());
            cardPricingRepository.save(cardPricing);
        } else {
            System.out.println("Db de veri var");
        }


    }
}
