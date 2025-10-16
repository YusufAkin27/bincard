package akin.city_card.initializer;

import akin.city_card.buscard.model.BusCard;
import akin.city_card.buscard.model.CardStatus;
import akin.city_card.buscard.model.CardType;
import akin.city_card.buscard.repository.BusCardRepository;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;

@Component
@RequiredArgsConstructor
@Order(10)
public class BusCardDataInitializer implements ApplicationRunner {

    private final BusCardRepository busCardRepository;
    private final UserRepository userRepository;

    private static final Random random = new Random();

    @Override
    public void run(ApplicationArguments args) {
        List<User> users = userRepository.findAll();
        if (busCardRepository.count() == 0 && users.size() >= 10) {
            List<BusCard> cards = IntStream.range(0, 10)
                    .mapToObj(i -> createCard(i, users.get(i)))
                    .toList();

            busCardRepository.saveAll(cards);
            System.out.println(">> 10 otobüs kartı eklendi.");
        }
    }

    private BusCard createCard(int i, User user) {
        BusCard card = new BusCard();
        card.setCardNumber("CARD-" + (1000 + i));
        card.setFullName(user.getProfileInfo().getName() + " " + user.getProfileInfo().getSurname());
        card.setType(CardType.TAM);
        card.setBalance(BigDecimal.valueOf(100 + random.nextInt(200)));
        card.setStatus(CardStatus.ACTIVE);
        card.setActive(true);
        card.setIssueDate(LocalDate.now());
        card.setExpiryDate(LocalDate.now().plusYears(3));
        return card;
    }
}
