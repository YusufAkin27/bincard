package akin.city_card.wallet.repository;

import akin.city_card.user.model.User;
import akin.city_card.wallet.model.Wallet;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface WalletRepository extends JpaRepository<Wallet, Long> {
    Optional<Wallet> findByUser(User user);

    Wallet findByWiban(String identifier);
}
