package akin.city_card.wallet.service.abstracts;

import akin.city_card.bus.exceptions.UnauthorizedAccessException;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.core.response.IdentityVerificationRequestDTO;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import akin.city_card.user.model.RequestStatus;
import akin.city_card.wallet.core.request.ProcessIdentityRequest;
import akin.city_card.wallet.core.request.CreateWalletRequest;
import akin.city_card.wallet.core.request.TopUpBalanceRequest;
import akin.city_card.wallet.core.request.WalletTransferRequest;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.core.response.WalletStatsDTO;
import akin.city_card.wallet.exceptions.*;
import akin.city_card.wallet.model.WalletActivityType;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

public interface WalletService {
    DataResponseMessage<BigDecimal> getWalletBalance(String phone) throws WalletNotFoundException, UserNotFoundException, WalletNotActiveException;
    ResponseMessage transfer(String senderPhone,@Valid WalletTransferRequest walletTransfer) throws UserNotFoundException, ReceiverNotFoundException, WalletNotFoundException, ReceiverWalletNotFoundException, WalletNotActiveException, ReceiverWalletNotActiveException, InsufficientFundsException;
    ResponseMessage toggleWalletStatus(String phone, boolean isActive) throws WalletNotActiveException, WalletNotFoundException, UserNotFoundException, WalletDeactivationException;
    ResponseMessage createWallet(@Valid String phone, CreateWalletRequest createWalletRequest) throws UserNotFoundException, OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException, VideoSizeLargerException, FileFormatCouldNotException;


    DataResponseMessage<?> getTransferDetail(String username, Long id) throws UnauthorizedAccessException, UserNotFoundException, TransferNotFoundException;

    DataResponseMessage<List<BigDecimal>> getBalanceHistory(String username, LocalDate start, LocalDate end);

    ResponseMessage changeStatusAsAdmin(String username, String userNumber, boolean activate, String statusReason);


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


    DataResponseMessage<Map<String, Object>> getSystemStats(String username);

    ResponseMessage forceTransaction(String username, String userPhone, BigDecimal amount, String reason);

    DataResponseMessage<List<?>> getSuspiciousActivities(String username, int page, int size);

    DataResponseMessage<byte[]> exportTransactionsExcel(String username, LocalDate start, LocalDate end) throws UserNotFoundException, UnauthorizedAreaException;
    DataResponseMessage<byte[]> exportTransactionsPDF(String username, LocalDate start, LocalDate end);

    ResponseMessage topUp(@Valid String username, TopUpBalanceRequest topUpBalanceRequest) throws UserNotFoundException, WalletNotFoundException;

    ResponseMessage approveOrReject(@Valid ProcessIdentityRequest request, String username) throws UserNotFoundException, UnauthorizedAreaException, IdentityVerificationRequestNotFoundException, AlreadyWalletUserException;

    DataResponseMessage<Page<IdentityVerificationRequestDTO>> getIdentityRequests(String username, RequestStatus status, LocalDate startDate, LocalDate endDate, int page, int size, String sortBy, String sortDir) throws UserNotFoundException, UnauthorizedAreaException;

    WalletDTO getMyWallet(String username) throws WalletNotFoundException, WalletNotActiveException, UserNotFoundException;

    DataResponseMessage<Page<WalletActivityDTO>> getActivities(String username, WalletActivityType type, LocalDate start, LocalDate end, Pageable pageable) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException;

    DataResponseMessage<Page<WalletDTO>> getAllWallets(String username, Pageable pageable);
}

