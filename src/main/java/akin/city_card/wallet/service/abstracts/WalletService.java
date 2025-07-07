package akin.city_card.wallet.service.abstracts;

import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.wallet.core.request.CreateWalletRequest;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.core.response.WalletStatsDTO;
import akin.city_card.wallet.model.WalletActivityType;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

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

    ResponseMessage transferToWiban(String username, String receiverWiban, BigDecimal amount, String description);

    ResponseMessage transferToEmail(String username, String receiverEmail, BigDecimal amount, String description);

    ResponseMessage withdrawToBank(String username, BigDecimal amount, String bankAccount, String bankCode);

    DataResponseMessage<List<?>> getWithdrawHistory(String username, int page, int size);

    DataResponseMessage<WalletStatsDTO> getWalletStats(String username, LocalDate start, LocalDate end);

    DataResponseMessage<byte[]> getMonthlyReport(String username, int year, int month);

    DataResponseMessage<byte[]> getYearlyReport(String username, int year);

    DataResponseMessage<WalletDTO> getWalletInfo(String username);

    ResponseMessage setNotificationSettings(String username, boolean emailNotifications, boolean smsNotifications, boolean pushNotifications);

    DataResponseMessage<?> getNotificationSettings(String username);

    DataResponseMessage<List<WalletDTO>> getAllWallets(String username, int page, int size);

    DataResponseMessage<Map<String, Object>> getSystemStats(String username);

    ResponseMessage forceTransaction(String username, String userPhone, BigDecimal amount, String reason);

    DataResponseMessage<List<?>> getSuspiciousActivities(String username, int page, int size);

    DataResponseMessage<byte[]> exportTransactionsCSV(String username, LocalDate start, LocalDate end);

    DataResponseMessage<byte[]> exportTransactionsPDF(String username, LocalDate start, LocalDate end);
}

