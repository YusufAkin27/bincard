package akin.city_card.wallet.repository;

import akin.city_card.wallet.model.WalletStatusLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WalletStatusLogRepository extends JpaRepository<WalletStatusLog, Long> {
}
