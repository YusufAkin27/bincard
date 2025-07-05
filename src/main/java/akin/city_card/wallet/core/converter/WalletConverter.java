package akin.city_card.wallet.core.converter;

import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.model.Wallet;

public interface WalletConverter {
    WalletDTO convertToDTO(Wallet wallet);
}
