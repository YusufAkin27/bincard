/*package akin.city_card.initializer;

import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletStatus;
import akin.city_card.wallet.repository.WalletRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.List;
import java.util.Random;

@Component
@RequiredArgsConstructor
public class WalletDataInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final WalletRepository walletRepository;

    private static final Random random = new Random();

    @Override
    public void run(ApplicationArguments args) {
        List<User> users = userRepository.findAllWithWallet(); // JOIN FETCH

        List<Wallet> wallets = users.stream()
                .filter(user -> user.getWallet() == null)
                .map(this::createWalletForUser)
                .toList();

        walletRepository.saveAll(wallets);

        wallets.forEach(wallet ->
                System.out.println("→ Cüzdan oluşturuldu: " +
                        wallet.getUser().getUserNumber() + " | Bakiye: " + wallet.getBalance()));

        System.out.println(">> " + wallets.size() + " adet kullanıcı cüzdanı oluşturuldu.");
    }


    private Wallet createWalletForUser(User user) {
        BigDecimal randomBalance = BigDecimal.valueOf(100 + random.nextInt(901)); // 100 – 1000 arası
        Wallet wallet = Wallet.builder()
                .user(user)
                .balance(randomBalance)
                .status(WalletStatus.ACTIVE)
                .currency("TRY")
                .build();

        user.setWallet(wallet);

        return wallet;
    }
}


 */