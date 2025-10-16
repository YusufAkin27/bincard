package akin.city_card.wallet.core.converter;

import akin.city_card.wallet.core.response.TransferDetailsDTO;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.core.response.WalletTransactionDTO;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletActivity;
import akin.city_card.wallet.model.WalletTransaction;
import akin.city_card.wallet.model.WalletTransfer;

public interface WalletConverter {
    WalletDTO convertToDTO(Wallet wallet);

    TransferDetailsDTO convertToTransferDTO(WalletTransfer walletTransfer);

    WalletActivityDTO convertWalletActivityDTO(WalletActivity walletActivity);

    WalletTransactionDTO convertToTransactionDTO(WalletTransaction walletTransaction);

}
