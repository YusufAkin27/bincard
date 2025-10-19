package akin.city_card.wallet.repository;

import akin.city_card.wallet.model.WalletActivity;
import akin.city_card.wallet.model.WalletActivityType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface WalletActivityRepository extends JpaRepository<WalletActivity, Long> {
    Page<WalletActivity> findByWalletIdAndActivityDateBetween(
            Long walletId, LocalDateTime start, LocalDateTime end, Pageable pageable);

    Page<WalletActivity> findByWalletIdAndActivityTypeAndActivityDateBetween(
            Long walletId, WalletActivityType type, LocalDateTime start, LocalDateTime end, Pageable pageable);


    List<WalletActivity> findTop10ByWalletIdOrderByActivityDateDesc(Long walletId);
}
