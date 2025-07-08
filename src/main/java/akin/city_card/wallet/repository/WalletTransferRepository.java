package akin.city_card.wallet.repository;

import akin.city_card.wallet.model.WalletTransfer;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface WalletTransferRepository extends JpaRepository<WalletTransfer, Long> {
}
