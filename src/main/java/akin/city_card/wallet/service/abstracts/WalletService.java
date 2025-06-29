package akin.city_card.wallet.service.abstracts;

import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.wallet.core.request.CreateWalletRequest;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.model.WalletActivityType;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

public interface WalletService {
    DataResponseMessage<BigDecimal> getWalletBalance(String phone);
    ResponseMessage transfer(String senderPhone, String receiverPhone, BigDecimal amount);
    ResponseMessage deactivateWallet(String phone);
    ResponseMessage activateWallet(String phone);
    DataResponseMessage<List<WalletActivityDTO>> getActivities(String phone, WalletActivityType type, LocalDate start, LocalDate end);

    DataResponseMessage<WalletDTO> createWallet(String phone, CreateWalletRequest createWalletRequest);

    DataResponseMessage<List<WalletActivityDTO>> getActivitiesPaged(String username, WalletActivityType type, int page, int size);

    DataResponseMessage<?> getTransferDetail(String username, Long id);

    DataResponseMessage<List<BigDecimal>> getBalanceHistory(String username, LocalDate start, LocalDate end);

    ResponseMessage changeStatusAsAdmin(String username, String userNumber, boolean activate, String statusReason);

    ResponseMessage topUp(String username, BigDecimal amount, String cardNumber, String cardExpiry, String cardCvc);
}

