package akin.city_card.wallet.service.concretes;

import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.wallet.core.request.CreateWalletRequest;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.model.WalletActivityType;
import akin.city_card.wallet.service.abstracts.WalletService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

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
}
