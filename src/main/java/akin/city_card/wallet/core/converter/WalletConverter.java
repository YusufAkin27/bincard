package akin.city_card.wallet.core.converter;

import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletActivity;

public interface WalletConverter {
    WalletDTO convertToDTO(Wallet wallet);
    WalletActivityDTO  convertWalletActivityDTO(WalletActivity walletActivity);
}
