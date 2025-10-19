package akin.city_card.initializer;

import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletStatus;
import akin.city_card.wallet.repository.WalletRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.List;
import java.util.Random;

@Component
@RequiredArgsConstructor
@Order(4)  // Dördüncü sırada - Kullanıcılar oluştuktan sonra
public class WalletDataInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final WalletRepository walletRepository;

    private static final Random random = new Random();

    @Override
    public void run(ApplicationArguments args) {
        // Sadece USER rolüne sahip kullanıcıları al (Admin, Driver değil)
        List<User> users = userRepository.findAll().stream()
                .filter(user -> user.getRoles().contains(akin.city_card.security.entity.Role.USER))
                .filter(user -> !user.getRoles().contains(akin.city_card.security.entity.Role.ADMIN))
                .filter(user -> !user.getRoles().contains(akin.city_card.security.entity.Role.DRIVER))
                .toList();

        if (users.isEmpty()) {
            return;
        }

        // Zaten cüzdanı olan kullanıcıları kontrol et
        long existingWalletCount = walletRepository.count();
        if (existingWalletCount > 0) {
           return;
        }

        List<Wallet> wallets = users.stream()
                .map(this::createWalletForUser)
                .toList();

        walletRepository.saveAll(wallets);


}

    private Wallet createWalletForUser(User user) {
        BigDecimal randomBalance = BigDecimal.valueOf(100 + random.nextInt(901)); // 100 – 1000 TL arası

        return Wallet.builder()
                .user(user)
                .balance(randomBalance)
                .status(WalletStatus.ACTIVE)
                .currency("TRY")
                .build();
    }
}
