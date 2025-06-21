package akin.city_card.wallet.repository;

import akin.city_card.wallet.model.WalletActivity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WalletActivityRepository extends JpaRepository<WalletActivity, Integer> {
}
