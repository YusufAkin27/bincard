package akin.city_card.wallet.core.converter;

import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.model.Wallet;
import org.springframework.stereotype.Component;

@Component
public class WalletConverterImpl implements WalletConverter {

    @Override
    public WalletDTO convertToDTO(Wallet wallet) {
        if (wallet == null) {
            return null;
        }

        return WalletDTO.builder()
                .walletId(wallet.getId())
                .userId(wallet.getUser() != null ? wallet.getUser().getId() : null)
                .currency(wallet.getCurrency())
                .balance(wallet.getBalance())
                .status(wallet.getStatus())
                .activeTransferCode(wallet.getActiveTransferCode())
                .transferCodeExpiresAt(wallet.getTransferCodeExpiresAt())
                .totalTransactionCount(wallet.getTotalTransactionCount())
                .createdAt(wallet.getCreatedAt()) // AuditableEntity'den miras alıyor
                .lastUpdated(wallet.getLastUpdated())
                .build();
    }
}
