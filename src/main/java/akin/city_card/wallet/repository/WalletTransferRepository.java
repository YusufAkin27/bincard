package akin.city_card.wallet.repository;

import akin.city_card.wallet.model.WalletTransfer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface WalletTransferRepository extends JpaRepository<WalletTransfer, Long> {

    @Query("SELECT wt FROM WalletTransfer wt WHERE wt.senderWallet.id = :walletId AND wt.initiatedAt BETWEEN :start AND :end")
    List<WalletTransfer> findRecentTransfersByWalletId(
            @Param("walletId") Long walletId,
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end
    );

}
