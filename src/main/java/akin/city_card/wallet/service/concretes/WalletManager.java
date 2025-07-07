package akin.city_card.wallet.service.concretes;

import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.wallet.core.request.CreateWalletRequest;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.core.response.WalletStatsDTO;
import akin.city_card.wallet.model.WalletActivityType;
import akin.city_card.wallet.service.abstracts.WalletService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;


@Service
@RequiredArgsConstructor
public class WalletManager implements WalletService {


    @Override
    public DataResponseMessage<BigDecimal> getWalletBalance(String phone) {
        return null;
    }

    @Override
    public ResponseMessage transfer(String senderPhone, String receiverPhone, BigDecimal amount) {
        return null;
    }

    @Override
    public ResponseMessage deactivateWallet(String phone) {
        return null;
    }

    @Override
    public ResponseMessage activateWallet(String phone) {
        return null;
    }

    @Override
    public DataResponseMessage<List<WalletActivityDTO>> getActivities(String phone, WalletActivityType type, LocalDate start, LocalDate end) {
        return null;
    }

    @Override
    public DataResponseMessage<WalletDTO> createWallet(String phone, CreateWalletRequest createWalletRequest) {
        return null;
    }

    @Override
    public DataResponseMessage<List<WalletActivityDTO>> getActivitiesPaged(String username, WalletActivityType type, int page, int size) {
        return null;
    }

    @Override
    public DataResponseMessage<?> getTransferDetail(String username, Long id) {
        return null;
    }

    @Override
    public DataResponseMessage<List<BigDecimal>> getBalanceHistory(String username, LocalDate start, LocalDate end) {
        return null;
    }

    @Override
    public ResponseMessage changeStatusAsAdmin(String username, String userNumber, boolean activate, String statusReason) {
        return null;
    }

    @Override
    public ResponseMessage topUp(String username, BigDecimal amount, String cardNumber, String cardExpiry, String cardCvc) {
        return null;
    }

    @Override
    public ResponseMessage transferToWiban(String username, String receiverWiban, BigDecimal amount, String description) {
        return null;
    }

    @Override
    public ResponseMessage transferToEmail(String username, String receiverEmail, BigDecimal amount, String description) {
        return null;
    }

    @Override
    public ResponseMessage withdrawToBank(String username, BigDecimal amount, String bankAccount, String bankCode) {
        return null;
    }

    @Override
    public DataResponseMessage<List<?>> getWithdrawHistory(String username, int page, int size) {
        return null;
    }

    @Override
    public DataResponseMessage<WalletStatsDTO> getWalletStats(String username, LocalDate start, LocalDate end) {
        return null;
    }

    @Override
    public DataResponseMessage<byte[]> getMonthlyReport(String username, int year, int month) {
        return null;
    }

    @Override
    public DataResponseMessage<byte[]> getYearlyReport(String username, int year) {
        return null;
    }

    @Override
    public DataResponseMessage<WalletDTO> getWalletInfo(String username) {
        return null;
    }

    @Override
    public ResponseMessage setNotificationSettings(String username, boolean emailNotifications, boolean smsNotifications, boolean pushNotifications) {
        return null;
    }

    @Override
    public DataResponseMessage<?> getNotificationSettings(String username) {
        return null;
    }

    @Override
    public DataResponseMessage<List<WalletDTO>> getAllWallets(String username, int page, int size) {
        return null;
    }

    @Override
    public DataResponseMessage<Map<String, Object>> getSystemStats(String username) {
        return null;
    }

    @Override
    public ResponseMessage forceTransaction(String username, String userPhone, BigDecimal amount, String reason) {
        return null;
    }

    @Override
    public DataResponseMessage<List<?>> getSuspiciousActivities(String username, int page, int size) {
        return null;
    }

    @Override
    public DataResponseMessage<byte[]> exportTransactionsCSV(String username, LocalDate start, LocalDate end) {
        return null;
    }

    @Override
    public DataResponseMessage<byte[]> exportTransactionsPDF(String username, LocalDate start, LocalDate end) {
        return null;
    }

}
