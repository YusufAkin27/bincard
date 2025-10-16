package akin.city_card.wallet.repository;

import akin.city_card.wallet.model.TransactionStatus;
import akin.city_card.wallet.model.TransactionType;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletTransaction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface WalletTransactionRepository extends JpaRepository<WalletTransaction, Long> {
    List<WalletTransaction> findByTypeInAndTimestampBetween(
            List<TransactionType> types,
            LocalDateTime start,
            LocalDateTime end
    );

    List<WalletTransaction> findAllByWalletAndTimestampBetweenOrderByTimestampAsc(Wallet wallet, LocalDateTime start, LocalDateTime end);

    List<WalletTransaction> findAllByWalletAndTimestampBetweenAndStatus(Wallet wallet, LocalDateTime localDateTime, LocalDateTime localDateTime1, TransactionStatus transactionStatus);

    long countByStatus(TransactionStatus status);

    Page<WalletTransaction> findByWalletIdAndType(Long walletId, TransactionType type, Pageable pageable);
}
