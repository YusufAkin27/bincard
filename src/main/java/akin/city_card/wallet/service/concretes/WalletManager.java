package akin.city_card.wallet.service.concretes;

import akin.city_card.bus.exceptions.UnauthorizedAccessException;
import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.news.model.PlatformType;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.service.FCMService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.Role;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.user.core.converter.UserConverter;
import akin.city_card.user.core.response.IdentityVerificationRequestDTO;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import akin.city_card.user.model.*;
import akin.city_card.user.repository.IdentityVerificationRequestRepository;
import akin.city_card.user.repository.UserIdentityInfoRepository;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.service.concretes.PhoneNumberFormatter;
import akin.city_card.wallet.core.converter.WalletConverter;
import akin.city_card.wallet.core.request.CreateWalletRequest;
import akin.city_card.wallet.core.request.ProcessIdentityRequest;
import akin.city_card.wallet.core.request.TopUpBalanceRequest;
import akin.city_card.wallet.core.request.WalletTransferRequest;
import akin.city_card.wallet.core.response.*;
import akin.city_card.wallet.exceptions.*;
import akin.city_card.wallet.model.*;
import akin.city_card.wallet.repository.*;
import akin.city_card.wallet.service.abstracts.WalletService;
import com.iyzipay.Options;
import com.iyzipay.model.*;
import com.iyzipay.model.Currency;
import com.iyzipay.model.Locale;
import com.iyzipay.request.CreatePaymentRequest;
import com.iyzipay.request.RetrievePaymentRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.util.*;


@Service
@RequiredArgsConstructor
@Slf4j
public class WalletManager implements WalletService {
    private final Options iyzicoOptions;
    private final UserRepository userRepository;
    private final WalletRepository walletRepository;
    private final WalletTransferRepository walletTransferRepository;
    private final WalletActivityRepository walletActivityRepository;
    private final MediaUploadService mediaUploadService;
    private final UserIdentityInfoRepository userIdentityInfoRepository;
    private final SecurityUserRepository securityUserRepository;
    private final IdentityVerificationRequestRepository identityVerificationRequestRepository;
    private final WalletTransactionRepository walletTransactionRepository;
    private final WalletStatusLogRepository walletStatusLogRepository;
    private final WalletConverter walletConverter;
    private final TopUpSessionCache topUpSessionCache;
    private final UserConverter userConverter;
    private final FCMService fcmService;


    private User findReceiverByIdentifier(String identifier) throws UserNotFoundException {
        if (identifier == null) return null;

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(identifier);
        if (PhoneNumberFormatter.PhoneValid(normalizedPhone)) {
            return userRepository.findByUserNumber(normalizedPhone).orElseThrow(UserNotFoundException::new);
        }

        if (identifier.startsWith("WBN-")) {
            Optional<Wallet> wallet = walletRepository.findByWiban(identifier);
            return wallet.isPresent() ? wallet.get().getUser() : null;
        }

        if (identifier.contains("@")) {
            return userRepository.findByProfileInfo_Email(identifier);
        }

        if (identifier.matches("\\d{11}")) {
            return userRepository.findByIdentityInfo_NationalId(identifier);
        }

        return null;
    }

    private String normalizeName(String input) {
        if (input == null) return "";

        return input.replaceAll("[^\\p{L}]", "").toLowerCase();
    }

    @Override
    public ResponseMessage transfer(String senderPhone, WalletTransferRequest walletTransferRequest) throws UserNotFoundException, ReceiverNotFoundException, WalletNotFoundException, ReceiverWalletNotFoundException, WalletNotActiveException, ReceiverWalletNotActiveException, InsufficientFundsException, NameAndSurnameAreWrongException {
        User sender = userRepository.findByUserNumber(PhoneNumberFormatter.normalizeTurkishPhoneNumber(senderPhone)).orElseThrow(UserNotFoundException::new);

        User receiver = findReceiverByIdentifier(walletTransferRequest.getReceiverIdentifier());
        if (receiver == null) {
            throw new ReceiverNotFoundException();
        }

        if (sender.getWallet() == null) {
            throw new WalletNotFoundException();
        }
        if (receiver.getWallet() == null) {
            throw new ReceiverWalletNotFoundException();
        }
        if (!sender.getWallet().getStatus().equals(WalletStatus.ACTIVE)) {
            throw new WalletNotActiveException();
        }
        if (!receiver.getWallet().getStatus().equals(WalletStatus.ACTIVE)) {
            throw new ReceiverWalletNotActiveException();
        }

        Wallet senderWallet = sender.getWallet();
        Wallet receiverWallet = receiver.getWallet();
        BigDecimal transferAmount = walletTransferRequest.getAmount();

        if (senderWallet.getBalance().compareTo(transferAmount) < 0) {
            throw new InsufficientFundsException();
        }
        // ✅ Alıcının adı soyadı kontrolü
        String providedFullName = normalizeName(walletTransferRequest.getReceiverNameAndSurname());
        String actualFullName;

        if (receiver.getProfileInfo() != null) {
            actualFullName = normalizeName(receiver.getProfileInfo().getName() + receiver.getProfileInfo().getSurname());
        } else {
            actualFullName = "";
        }

        if (!actualFullName.equals(providedFullName)) {
            throw new NameAndSurnameAreWrongException();
        }


        WalletTransfer walletTransfer = new WalletTransfer();
        walletTransfer.setAmount(transferAmount);
        walletTransfer.setReceiverWallet(receiverWallet);
        walletTransfer.setSenderWallet(senderWallet);
        walletTransfer.setStatus(TransferStatus.SUCCESS);
        walletTransfer.setDescription(walletTransferRequest.getDescription());
        walletTransfer.setCancellationReason(null);
        walletTransfer.setInitiatedAt(LocalDateTime.now());
        walletTransfer.setCompletedAt(LocalDateTime.now());
        walletTransfer.setVersion(1L);
        walletTransfer.setInitiatedByUserId(sender.getId()); // ✅ Eksik olan bu satır

        WalletTransfer savedTransfer = walletTransferRepository.save(walletTransfer);

        senderWallet.setBalance(senderWallet.getBalance().subtract(transferAmount));
        receiverWallet.setBalance(receiverWallet.getBalance().add(transferAmount));

        walletRepository.save(senderWallet);
        walletRepository.save(receiverWallet);

        WalletTransaction senderTransaction = WalletTransaction.builder()
                .wallet(senderWallet)
                .amount(transferAmount.negate())
                .type(TransactionType.TRANSFER_OUT)
                .status(TransactionStatus.SUCCESS)
                .timestamp(LocalDateTime.now())
                .description("Transfer to " + receiver.getUserNumber())
                .externalReference("TRF-" + savedTransfer.getId())
                .userId(sender.getId())
                .version(1L)
                .build();

        WalletTransaction savedSenderTransaction = walletTransactionRepository.save(senderTransaction);

        // Alıcı için transaction kaydı oluştur
        WalletTransaction receiverTransaction = WalletTransaction.builder()
                .wallet(receiverWallet)
                .amount(transferAmount) // Pozitif miktar (para geliyor)
                .type(TransactionType.TRANSFER_IN)
                .status(TransactionStatus.SUCCESS)
                .timestamp(LocalDateTime.now())
                .description("Transfer from " + sender.getUserNumber())
                .externalReference("TRF-" + savedTransfer.getId())
                .userId(receiver.getId())
                .version(1L)
                .build();

        WalletTransaction savedReceiverTransaction = walletTransactionRepository.save(receiverTransaction);

        WalletActivity senderActivity = WalletActivity.builder()
                .walletId(senderWallet.getId())
                .activityType(WalletActivityType.TRANSFER_SENT)
                .transactionId(savedSenderTransaction.getId())
                .transferId(savedTransfer.getId())
                .activityDate(LocalDateTime.now())
                .description("Para transferi gönderildi: " + receiver.getUserNumber())
                .version(1L)
                .build();

        walletActivityRepository.save(senderActivity);


        WalletActivity receiverActivity = WalletActivity.builder()
                .walletId(receiverWallet.getId())
                .activityType(WalletActivityType.TRANSFER_RECEIVED)
                .transactionId(savedReceiverTransaction.getId())
                .transferId(savedTransfer.getId())
                .activityDate(LocalDateTime.now())
                .description("Para transferi alındı: " + sender.getUserNumber())
                .version(1L)
                .build();

        walletActivityRepository.save(receiverActivity);

        fcmService.sendNotificationToToken(
                receiver,
                "Para Transferi Alındı",
                String.format("%s numaralı kullanıcıdan ₺%s tutarında para aldınız.", sender.getUserNumber(), transferAmount),
                NotificationType.INFO,
                null // opsiyonel: hedef ekran URL'si gibi bir şey varsa yaz
        );

        String msg = String.format("transferId: %d\namount: %s\nsenderBalance: %s\nreceiverPhone: %s",
                savedTransfer.getId(), transferAmount, senderWallet.getBalance(), receiver.getUserNumber());

        return new ResponseMessage(msg, true);
    }

    @Override
    public String getWibanToName(String input) {
        if (input == null || input.trim().isEmpty()) {
            return "";
        }

        Optional<User> user = Optional.empty();
        String cleanedInput = input.trim();

        // WIBAN ile arama
        if (cleanedInput.startsWith("WBN-")) {
            Optional<Wallet> wallet = walletRepository.findByWiban(cleanedInput);
            if (wallet.isPresent() && wallet.get().getUser() != null) {
                user = Optional.of(wallet.get().getUser());
            }
        }

        // Telefon numarası ile arama
        else if (PhoneNumberFormatter.PhoneValid(cleanedInput)) {
            String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(cleanedInput);
            user = userRepository.findByUserNumber(normalizedPhone);
        }

        // TC Kimlik numarası ile arama
        else if (cleanedInput.matches("^\\d{11}$")) {
            user = Optional.ofNullable(userRepository.findByIdentityInfo_NationalId(cleanedInput));
        }

        // E-posta ile arama
        else if (cleanedInput.contains("@")) {
            user = Optional.ofNullable(userRepository.findByProfileInfo_Email(cleanedInput));
        }

        if (user.isEmpty() || user.get() == null) {
            return "";
        }

        User foundUser = user.get();
        String name = null;
        String surname = null;

        if (foundUser.getProfileInfo() != null) {
            name = foundUser.getProfileInfo().getName();
            surname = foundUser.getProfileInfo().getSurname();
        }

        // İsim ve soyisim maskelenmiş döndürülür
        String maskedName = maskNameAndSurname(name, surname);
        return maskedName;
    }

    private String maskNameAndSurname(String name, String surname) {
        String namePart = (name != null && name.length() >= 2)
                ? name.substring(0, 2) + "*".repeat(name.length() - 2)
                : (name != null ? name : "");

        String surnamePart = (surname != null && surname.length() >= 2)
                ? surname.substring(0, 2) + "*".repeat(surname.length() - 2)
                : (surname != null ? surname : "");

        return (namePart + " " + surnamePart).trim();
    }


    @Override
    @Transactional
    public ResponseMessage toggleWalletStatus(String phone, boolean isActive) throws WalletNotFoundException, WalletNotActiveException, UserNotFoundException, WalletDeactivationException {

        User user = userRepository.findByUserNumber(phone).orElseThrow(UserNotFoundException::new);


        Wallet wallet = user.getWallet();
        if (wallet == null) {
            throw new WalletNotFoundException();
        }

        WalletStatus currentStatus = wallet.getStatus();

        if (isActive) {
            if (currentStatus == WalletStatus.ACTIVE) {
                return new ResponseMessage("Cüzdan zaten aktif durumda.", false);
            }

            if (currentStatus == WalletStatus.LOCKED) {
                return new ResponseMessage("Cüzdan kilitli, manuel müdahale gerektirir.", false);
            }

            wallet.setStatus(WalletStatus.ACTIVE);
        } else {
            if (currentStatus == WalletStatus.SUSPENDED) {
                return new ResponseMessage("Cüzdan zaten askıya alınmış durumda.", false);
            }

            if (currentStatus != WalletStatus.ACTIVE) {
                throw new WalletNotActiveException();
            }
            if (!isActive && wallet.getBalance().compareTo(BigDecimal.ZERO) > 0) {
                throw new WalletDeactivationException();
            }

            wallet.setStatus(WalletStatus.SUSPENDED);
        }

        wallet.setLastUpdated(LocalDateTime.now());

        WalletStatusLog statusLog = WalletStatusLog.builder()
                .wallet(wallet)
                .oldStatus(currentStatus)
                .newStatus(wallet.getStatus())
                .changedAt(LocalDateTime.now())
                .changedByUserId(user.getId())
                .reason(isActive
                        ? "Kullanıcı isteğiyle cüzdan yeniden aktive edildi."
                        : "Kullanıcı isteğiyle cüzdan askıya alındı.")
                .build();

        walletStatusLogRepository.save(statusLog);
        walletRepository.save(wallet);

        fcmService.sendNotificationToToken(
                user,
                "Cüzdan Durumu Güncellendi",
                isActive ? "Cüzdanınız yeniden aktifleştirildi." : "Cüzdanınız askıya alındı.",
                NotificationType.INFO,
                null // İsteğe bağlı yönlendirme URL'si
        );

        String message = isActive ? "Cüzdan başarıyla aktifleştirildi." : "Cüzdan başarıyla askıya alındı.";
        return new ResponseMessage(message, true);
    }


    @Override
    public DataResponseMessage<Page<WalletActivityDTO>> getActivities(String username, WalletActivityType type, LocalDate start, LocalDate end, Pageable pageable) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {

        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        ;


        Wallet wallet = user.getWallet();
        if (wallet == null) {
            throw new WalletNotFoundException();
        }
        if (!wallet.getStatus().equals(WalletStatus.ACTIVE)) {
            throw new WalletNotActiveException();
        }
        Long walletId = wallet.getId();

        LocalDateTime startDateTime = (start != null) ? start.atStartOfDay() : LocalDateTime.of(1970, 1, 1, 0, 0);
        LocalDateTime endDateTime = (end != null) ? end.atTime(23, 59, 59) : LocalDateTime.now().plusYears(10);

        Page<WalletActivity> activities;

        if (type != null) {
            activities = walletActivityRepository.findByWalletIdAndActivityTypeAndActivityDateBetween(
                    walletId, type, startDateTime, endDateTime, pageable);
        } else {
            activities = walletActivityRepository.findByWalletIdAndActivityDateBetween(
                    walletId, startDateTime, endDateTime, pageable);
        }

        Page<WalletActivityDTO> dtoPage = activities.map(walletConverter::convertWalletActivityDTO);

        return new DataResponseMessage<>(
                "Aktiviteler başarıyla getirildi.",
                true,
                dtoPage
        );
    }

    @Override
    public DataResponseMessage<Page<WalletDTO>> getAllWallets(String adminUsername, Pageable pageable) {
        Page<Wallet> walletPage = walletRepository.findAll(pageable);

        Page<WalletDTO> dtoPage = walletPage.map(walletConverter::convertToDTO);

        return new DataResponseMessage<>(
                "Tüm cüzdanlar başarıyla getirildi.",
                true,
                dtoPage
        );
    }


    @Override
    @Transactional
    public ResponseMessage createWallet(String phone, CreateWalletRequest request) throws UserNotFoundException, OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException, VideoSizeLargerException, FileFormatCouldNotException {
        User user = userRepository.findByUserNumber(phone).orElseThrow(UserNotFoundException::new);
        ;

        List<IdentityVerificationRequest> existingRequests = identityVerificationRequestRepository.findByRequestedBy(user);

        boolean hasPendingOrApproved = existingRequests.stream()
                .anyMatch(r -> r.getStatus() == RequestStatus.PENDING || r.getStatus() == RequestStatus.APPROVED);

        if (hasPendingOrApproved) {
            return new ResponseMessage("Kimlik doğrulama isteğiniz zaten işleniyor veya onaylanmış.", false);
        }
        if (request.getFrontCardPhoto() == null || request.getBackCardPhoto() == null) {
            throw new IllegalArgumentException("Kimlik fotoğrafları boş olamaz");
        }

        UserIdentityInfo identityInfo = UserIdentityInfo.builder()
                .nationalId(request.getNationalId())
                .birthDate(request.getBirthDate())
                .serialNumber(request.getSerialNumber())
                .gender(request.getGender())
                .motherName(request.getMotherName())
                .fatherName(request.getFatherName())
                .frontCardPhoto(mediaUploadService.uploadAndOptimizeMedia(request.getFrontCardPhoto()))
                .backCardPhoto(mediaUploadService.uploadAndOptimizeMedia(request.getBackCardPhoto()))
                .approved(false)
                .user(user)
                .build();
        userIdentityInfoRepository.save(identityInfo);

        IdentityVerificationRequest verificationRequest = IdentityVerificationRequest.builder()
                .identityInfo(identityInfo)
                .requestedBy(user)
                .requestedAt(LocalDateTime.now())
                .status(RequestStatus.PENDING)
                .build();
        identityVerificationRequestRepository.save(verificationRequest);


        return new ResponseMessage("Kimlik onay başvurusu alındı. ", true);
    }


    @Override
    public DataResponseMessage<TransferDetailsDTO> getTransferDetail(String username, Long id) throws UnauthorizedAccessException, UserNotFoundException, TransferNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);


        WalletTransfer transfer = walletTransferRepository.findById(id)
                .orElseThrow(TransferNotFoundException::new);

        Long userWalletId = user.getWallet() != null ? user.getWallet().getId() : null;

        if (!transfer.getSenderWallet().getId().equals(userWalletId) &&
                !transfer.getReceiverWallet().getId().equals(userWalletId)) {
            throw new UnauthorizedAccessException();
        }

        TransferDetailsDTO dto = walletConverter.convertToTransferDTO(transfer);

        return new DataResponseMessage<>("transfer", true, dto);
    }


    @Override
    public DataResponseMessage<List<BalanceHistoryDTO>> getBalanceHistory(String username, LocalDate start, LocalDate end) throws WalletNotFoundException, WalletNotActiveException, UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        if (user.getWallet() == null) {
            throw new WalletNotFoundException();
        }
        if (user.getWallet().getStatus() != WalletStatus.ACTIVE) {
            throw new WalletNotActiveException();
        }

        Wallet wallet = user.getWallet();
        List<WalletTransaction> transactions = walletTransactionRepository
                .findAllByWalletAndTimestampBetweenOrderByTimestampAsc(wallet,
                        start.atStartOfDay(), end.atTime(23, 59, 59));

        List<BalanceHistoryDTO> balanceHistory = new ArrayList<>();
        BigDecimal runningBalance = BigDecimal.ZERO;

        for (WalletTransaction tx : transactions) {
            if (tx.getStatus() != TransactionStatus.SUCCESS) {
                continue; // sadece başarılı işlemleri dahil et
            }

            // Gelen ya da giden paraya göre bakiye güncelle
            if (tx.getType() == TransactionType.TRANSFER_IN) {
                runningBalance = runningBalance.add(tx.getAmount());
            } else if (tx.getType() == TransactionType.TRANSFER_OUT) {
                runningBalance = runningBalance.subtract(tx.getAmount());
            }

            balanceHistory.add(BalanceHistoryDTO.builder()
                    .date(tx.getTimestamp())
                    .balance(runningBalance)
                    .build());
        }

        return new DataResponseMessage<>("bakiye geçmişi", true, balanceHistory);
    }


    @Override
    @Transactional
    public ResponseMessage changeStatusAsAdmin(String username, String userNumber, WalletStatus newStatus, String statusReason)
            throws UserNotFoundException, AdminOrSuperAdminNotFoundException, WalletNotFoundException {

        SecurityUser adminUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        if (!adminUser.hasRole("ADMIN") && !adminUser.hasRole("SUPERADMIN")) {
            throw new AdminOrSuperAdminNotFoundException();
        }

        User targetUser = userRepository.findByUserNumber(userNumber)
                .orElseThrow(UserNotFoundException::new);

        Wallet wallet = targetUser.getWallet();

        if (wallet == null) {
            throw new WalletNotFoundException();
        }

        WalletStatus currentStatus = wallet.getStatus();

        if (currentStatus == newStatus) {
            throw new IllegalStateException("Cüzdan zaten " + newStatus.name() + " durumunda.");
        }

        wallet.setStatus(newStatus);

        WalletStatusLog log = WalletStatusLog.builder()
                .wallet(wallet)
                .oldStatus(currentStatus)
                .newStatus(newStatus)
                .changedAt(LocalDateTime.now())
                .reason(statusReason)
                .changedByUserId(adminUser.getId())
                .build();

        wallet.getStatusLogs().add(log);
        walletRepository.save(wallet);

        if (newStatus == WalletStatus.SUSPENDED) {
            fcmService.sendNotificationToToken(
                    targetUser,
                    "Cüzdan Askıya Alındı",
                    "Cüzdanınız sistem yöneticisi tarafından askıya alındı. Sebep: " + statusReason,
                    NotificationType.ALERT,
                    null
            );
        }
        return new ResponseMessage("Cüzdan durumu başarıyla " + newStatus.name() + " olarak güncellendi.", true);
    }


    @Override
    public DataResponseMessage<WalletStatsDTO> getWalletStats(String username, LocalDate start, LocalDate end) throws WalletNotFoundException, UserNotFoundException {
        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        Wallet wallet = user.getWallet();

        if (wallet == null) {
            throw new WalletNotFoundException();
        }

        List<WalletTransaction> transactions = walletTransactionRepository
                .findAllByWalletAndTimestampBetweenAndStatus(wallet,
                        start.atStartOfDay(),
                        end.atTime(23, 59, 59),
                        TransactionStatus.SUCCESS);

        int totalCount = transactions.size();
        BigDecimal totalDeposit = BigDecimal.ZERO;
        BigDecimal totalWithdraw = BigDecimal.ZERO;

        for (WalletTransaction tx : transactions) {
            if (tx.getType() == TransactionType.TRANSFER_IN) {
                totalDeposit = totalDeposit.add(tx.getAmount());
            } else if (tx.getType() == TransactionType.TRANSFER_OUT) {
                totalWithdraw = totalWithdraw.subtract(tx.getAmount());
            }
        }

        BigDecimal netChange = totalDeposit.add(totalWithdraw); // withdraw zaten eksi

        WalletStatsDTO stats = WalletStatsDTO.builder()
                .totalTransactionCount(totalCount)
                .totalDepositAmount(totalDeposit)
                .totalWithdrawAmount(totalWithdraw.abs())
                .netChange(netChange)
                .build();

        return new DataResponseMessage<>("cüzdan istatistiklerin", true, stats);
    }

    private LocalDateTime getStartOfMonth(int year, int month) {
        return LocalDate.of(year, month, 1).atStartOfDay();
    }

    private LocalDateTime getEndOfMonth(int year, int month) {
        return YearMonth.of(year, month).atEndOfMonth().atTime(23, 59, 59);
    }

    private LocalDateTime getStartOfYear(int year) {
        return LocalDate.of(year, 1, 1).atStartOfDay();
    }

    private LocalDateTime getEndOfYear(int year) {
        return LocalDate.of(year, 12, 31).atTime(23, 59, 59);
    }

    private byte[] generateMockReport(List<WalletTransaction> transactions, String reportTitle) {
        StringBuilder reportBuilder = new StringBuilder();
        reportBuilder.append(reportTitle).append("\n");
        reportBuilder.append("Tarih, Tip, Tutar, Açıklama\n");

        for (WalletTransaction tx : transactions) {
            reportBuilder.append(tx.getTimestamp()).append(", ")
                    .append(tx.getType()).append(", ")
                    .append(tx.getAmount()).append(", ")
                    .append(tx.getDescription() == null ? "-" : tx.getDescription()).append("\n");
        }

        return reportBuilder.toString().getBytes(StandardCharsets.UTF_8); // geçici olarak text dosya gibi
    }

    @Override
    public DataResponseMessage<byte[]> getMonthlyReport(String username, int year, int month) throws UserNotFoundException, WalletNotFoundException {
        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        Wallet wallet = user.getWallet();
        if (wallet == null) {
            throw new WalletNotFoundException();
        }

        LocalDateTime start = getStartOfMonth(year, month);
        LocalDateTime end = getEndOfMonth(year, month);

        List<WalletTransaction> transactions = walletTransactionRepository
                .findAllByWalletAndTimestampBetweenAndStatus(wallet, start, end, TransactionStatus.SUCCESS);

        byte[] reportData = generateMockReport(transactions,
                String.format("%d-%02d Aylık Cüzdan Raporu", year, month));

        return new DataResponseMessage<>("aylık raporun", true, reportData);
    }


    @Override
    public DataResponseMessage<byte[]> getYearlyReport(String username, int year) throws UserNotFoundException, WalletNotFoundException {
        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        Wallet wallet = user.getWallet();
        if (wallet == null) {
            throw new WalletNotFoundException();
        }

        LocalDateTime start = getStartOfYear(year);
        LocalDateTime end = getEndOfYear(year);

        List<WalletTransaction> transactions = walletTransactionRepository
                .findAllByWalletAndTimestampBetweenAndStatus(wallet, start, end, TransactionStatus.SUCCESS);

        byte[] reportData = generateMockReport(transactions,
                String.format("%d Yıllık Cüzdan Raporu", year));

        return new DataResponseMessage<>("yıllık raporun", true, reportData);
    }


    @Override
    public DataResponseMessage<Map<String, Object>> getSystemStats(String username) throws AdminOrSuperAdminNotFoundException {
        SecurityUser adminUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(AdminOrSuperAdminNotFoundException::new);

        if (!adminUser.hasRole("ADMIN") && !adminUser.hasRole("SUPERADMIN")) {
            throw new AdminOrSuperAdminNotFoundException();
        }

        Map<String, Object> stats = new HashMap<>();

        // Kullanıcı verileri
        stats.put("totalUsers", userRepository.count());
        stats.put("activeUsers", userRepository.countByStatus(UserStatus.ACTIVE));
        stats.put("suspendedUsers", userRepository.countByStatus(UserStatus.SUSPENDED));

        // Cüzdan istatistikleri
        stats.put("totalWallets", walletRepository.count());
        stats.put("totalBalance", walletRepository.sumAllBalances());
        stats.put("activeWallets", walletRepository.countByStatus(WalletStatus.ACTIVE));
        stats.put("lockedWallets", walletRepository.countByStatus(WalletStatus.LOCKED));

        // İşlem verileri
        stats.put("totalTransactions", walletTransactionRepository.count());
        stats.put("successfulTransactions", walletTransactionRepository.countByStatus(TransactionStatus.SUCCESS));
        stats.put("failedTransactions", walletTransactionRepository.countByStatus(TransactionStatus.FAILED));

        // Zaman verisi
        stats.put("serverTime", LocalDateTime.now());

        return new DataResponseMessage<>("sistem istatistikleri", true, stats);
    }

    @Override
    @Transactional
    public ResponseMessage forceTransaction(String username, String userPhone, BigDecimal amount, String reason) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {
        User user = userRepository.findByUserNumber(userPhone)
                .orElseThrow(UserNotFoundException::new);

        Wallet wallet = user.getWallet();
        if (wallet == null) {
            throw new WalletNotFoundException();
        }

        if (wallet.getStatus() != WalletStatus.ACTIVE) {
            throw new WalletNotActiveException();
        }

        WalletTransaction transaction = WalletTransaction.builder()
                .wallet(wallet)
                .amount(amount)
                .type(amount.signum() >= 0 ? TransactionType.FORCE_CREDIT : TransactionType.FORCE_DEBIT)
                .status(TransactionStatus.SUCCESS)
                .description("Manuel işlem: " + reason)
                .timestamp(LocalDateTime.now())
                .build();

        wallet.setBalance(wallet.getBalance().add(amount));

        walletTransactionRepository.save(transaction);
        walletRepository.save(wallet);

        return new ResponseMessage("İşlem başarılı: " + reason, true);
    }


    @Override
    public DataResponseMessage<PageDTO<TransferDetailsDTO>> getSuspiciousActivities(String username, int page, int size) throws AdminOrSuperAdminNotFoundException {
        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(AdminOrSuperAdminNotFoundException::new);

        List<WalletTransfer> allTransfers = walletTransferRepository.findAll();

        List<TransferDetailsDTO> suspicious = allTransfers.stream()
                .filter(this::isSuspicious)
                .map(walletConverter::convertToTransferDTO)
                .toList();

        int total = suspicious.size();
        int fromIndex = Math.min(page * size, total);
        int toIndex = Math.min(fromIndex + size, total);
        List<TransferDetailsDTO> pageContent = suspicious.subList(fromIndex, toIndex);

        PageDTO<TransferDetailsDTO> dto = new PageDTO<>(
                pageContent,
                page,
                size,
                total,
                (int) Math.ceil((double) total / size),
                page == 0,
                toIndex == total
        );

        return new DataResponseMessage<>("Tüm şüpheli işlemler başarıyla listelendi", true, dto);
    }


    private boolean isSuspicious(WalletTransfer transfer) {
        BigDecimal amount = transfer.getAmount();
        LocalDateTime time = transfer.getInitiatedAt();
        String desc = transfer.getDescription() != null ? transfer.getDescription().toLowerCase() : "";
        TransferStatus status = transfer.getStatus();
        String cancellationReason = transfer.getCancellationReason();

        boolean isHighAmount = amount != null && amount.compareTo(BigDecimal.valueOf(10_000)) > 0;
        boolean isMidnightActivity = time != null && time.getHour() >= 0 && time.getHour() < 5;
        boolean isSelfTransfer = transfer.getSenderWallet().getId().equals(transfer.getReceiverWallet().getId());
        boolean isCancelledWithoutReason = status == TransferStatus.CANCELLED && (cancellationReason == null || cancellationReason.isBlank());
        boolean hasSuspiciousKeywords = desc.matches(".*(şüpheli|belirsiz|hack|fraud|çalıntı|illegal|izinsiz).*");

        List<WalletTransfer> recentTransfers = walletTransferRepository
                .findRecentTransfersByWalletId(transfer.getSenderWallet().getId(), time.minusMinutes(2), time.plusMinutes(2));
        boolean isRapidSequence = recentTransfers.size() > 3;

        return isHighAmount || isMidnightActivity || isSelfTransfer || isCancelledWithoutReason || hasSuspiciousKeywords || isRapidSequence;
    }


    @Override
    public DataResponseMessage<byte[]> exportTransactionsExcel(String username, LocalDate start, LocalDate end)
            throws UserNotFoundException, UnauthorizedAreaException {

        Optional<SecurityUser> securityUserOpt = securityUserRepository.findByUserNumber(username);
        if (securityUserOpt.isEmpty()) {
            throw new UserNotFoundException();
        }

        SecurityUser user = securityUserOpt.get();

        boolean isAdmin = user.getRoles().contains(Role.ADMIN) || user.getRoles().contains(Role.SUPERADMIN);
        if (!isAdmin) {
            throw new UnauthorizedAreaException();
        }

        LocalDateTime startDateTime = (start != null) ? start.atStartOfDay() : LocalDateTime.of(1970, 1, 1, 0, 0);
        LocalDateTime endDateTime = (end != null) ? end.atTime(23, 59, 59) : LocalDateTime.now();

        List<WalletTransaction> transactions = walletTransactionRepository
                .findByTypeInAndTimestampBetween(
                        List.of(TransactionType.TRANSFER_IN, TransactionType.TRANSFER_OUT),
                        startDateTime,
                        endDateTime
                );

        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet("Transfer Transactions");

            int rowNum = 0;
            Row header = sheet.createRow(rowNum++);
            String[] columns = {
                    "Transaction ID", "User ID", "User Number", "Wallet ID", "Wiban",
                    "Type", "Amount", "Status", "Timestamp", "Description"
            };

            for (int i = 0; i < columns.length; i++) {
                header.createCell(i).setCellValue(columns[i]);
            }

            for (WalletTransaction tx : transactions) {
                Row row = sheet.createRow(rowNum++);
                User txUser = userRepository.findById(tx.getUserId()).orElse(null);

                row.createCell(0).setCellValue(tx.getId());
                row.createCell(1).setCellValue(tx.getUserId());
                row.createCell(2).setCellValue(txUser != null ? txUser.getUserNumber() : "N/A");
                row.createCell(3).setCellValue(tx.getWallet() != null ? tx.getWallet().getId() : -1);
                row.createCell(4).setCellValue(tx.getWallet() != null ? tx.getWallet().getWiban() : "N/A");
                row.createCell(5).setCellValue(tx.getType().toString());
                row.createCell(6).setCellValue(tx.getAmount().toString());
                row.createCell(7).setCellValue(tx.getStatus().toString());
                row.createCell(8).setCellValue(tx.getTimestamp().toString());
                row.createCell(9).setCellValue(tx.getDescription() != null ? tx.getDescription() : "");
            }

            for (int i = 0; i < columns.length; i++) {
                sheet.autoSizeColumn(i);
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            workbook.write(outputStream);
            byte[] excelBytes = outputStream.toByteArray();

            return new DataResponseMessage<>("Excel başarıyla oluşturuldu.", true, excelBytes);

        } catch (IOException e) {
            throw new RuntimeException("Excel dosyası oluşturulamadı", e);
        }
    }


    @Override
    public DataResponseMessage<byte[]> exportTransactionsPDF(String username, LocalDate start, LocalDate end) {
        return null;
    }

    @Override
    public DataResponseMessage<Page<IdentityVerificationRequestDTO>> getIdentityRequests(
            String username,
            RequestStatus status,
            LocalDate startDate,
            LocalDate endDate,
            int page,
            int size,
            String sortBy,
            String sortDir
    ) throws UserNotFoundException, UnauthorizedAreaException {

        // Kullanıcı kontrolü
        Optional<SecurityUser> adminOpt = securityUserRepository.findByUserNumber(username);
        if (adminOpt.isEmpty()) {
            throw new UserNotFoundException();
        }

        SecurityUser admin = adminOpt.get();

        // Rol kontrolü
        boolean isAdmin = admin.getRoles().contains(Role.ADMIN) || admin.getRoles().contains(Role.SUPERADMIN);
        if (!isAdmin) {
            throw new UnauthorizedAreaException();
        }

        if (startDate != null && endDate != null && endDate.isBefore(startDate)) {
            throw new IllegalArgumentException("Bitiş tarihi, başlangıç tarihinden önce olamaz.");
        }

        Sort sort = Sort.by(Sort.Direction.fromString(sortDir.toUpperCase()), sortBy);
        Pageable pageable = PageRequest.of(page, size, sort);

        LocalDateTime defaultStart = LocalDateTime.of(1970, 1, 1, 0, 0);
        LocalDateTime defaultEnd = LocalDateTime.now().plusYears(1);

        LocalDateTime start = (startDate != null) ? startDate.atStartOfDay() : defaultStart;
        LocalDateTime end = (endDate != null)
                ? endDate.plusDays(1).atStartOfDay().minusNanos(1)
                : defaultEnd;

        Page<IdentityVerificationRequest> resultPage;
        if (status != null) {
            resultPage = identityVerificationRequestRepository
                    .findAllByStatusAndRequestedAtBetween(status, start, end, pageable);
        } else {
            resultPage = identityVerificationRequestRepository
                    .findAllByRequestedAtBetween(start, end, pageable);
        }

        Page<IdentityVerificationRequestDTO> dtoPage = resultPage.map(userConverter::convertToVerificationRequestDTO);

        return new DataResponseMessage<>(
                "Kimlik doğrulama başvuruları başarıyla getirildi.",
                true,
                dtoPage
        );
    }


    @Override
    public WalletDTO getMyWallet(String username) throws WalletNotFoundException, WalletNotActiveException, UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        ;
        Wallet wallet = user.getWallet();
        if (wallet == null) throw new WalletNotFoundException();
        if (!wallet.getStatus().equals(WalletStatus.ACTIVE)) throw new WalletNotActiveException();
        return walletConverter.convertToDTO(wallet);
    }


    @Override
    @Transactional
    public ResponseMessage topUp(String username, TopUpBalanceRequest topUpBalanceRequest)
            throws UserNotFoundException, WalletNotFoundException {

        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        if (!user.isEnabled()) {
            return new ResponseMessage("Kullanıcı hesabı aktif değil.", false);
        }

        Wallet wallet = user.getWallet();
        if (wallet == null) throw new WalletNotFoundException();

        if (!wallet.getStatus().equals(WalletStatus.ACTIVE)) {
            return new ResponseMessage("Cüzdan aktif değil. Durum: " + wallet.getStatus(), false);
        }

        if (topUpBalanceRequest.getAmount() == null || topUpBalanceRequest.getAmount().compareTo(BigDecimal.ONE) < 0) {
            return new ResponseMessage("Yükleme tutarı en az 1 TL olmalıdır.", false);
        }

        try {
            Options options = iyzicoOptions;

            // 1. Kart Bilgisi
            PaymentCard paymentCard = new PaymentCard();
            paymentCard.setCardHolderName(username);
            paymentCard.setCardNumber(topUpBalanceRequest.getCardNumber());
            paymentCard.setExpireMonth(topUpBalanceRequest.getCardExpiry().split("/")[0].trim());
            paymentCard.setExpireYear("20" + topUpBalanceRequest.getCardExpiry().split("/")[1].trim());
            paymentCard.setCvc(topUpBalanceRequest.getCardCvc());
            paymentCard.setRegisterCard(0);

            // 2. Buyer
            LocalDateTime lastLogin = user.getLoginHistory().isEmpty() ? LocalDateTime.now() : user.getLoginHistory().get(0).getLoginAt();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

            Buyer buyer = new Buyer();
            buyer.setId(user.getId().toString());
            buyer.setName(user.getProfileInfo().getName());
            buyer.setSurname(user.getProfileInfo().getSurname());
            buyer.setGsmNumber(user.getUserNumber());
            buyer.setEmail(Optional.ofNullable(user.getProfileInfo().getEmail()).orElse("default@mail.com"));
            buyer.setIdentityNumber(user.getIdentityInfo().getNationalId());
            buyer.setLastLoginDate(lastLogin.format(formatter));
            buyer.setRegistrationDate(user.getCreatedAt().format(formatter));
            buyer.setRegistrationAddress("Türkiye");
            buyer.setIp(user.getCurrentDeviceInfo().getIpAddress());
            buyer.setCity("İstanbul");
            buyer.setCountry("Turkey");
            buyer.setZipCode("34000");

            // 3. Adres
            Address address = new Address();
            address.setContactName(username);
            address.setCity("İstanbul");
            address.setCountry("Turkey");
            address.setAddress("Türkiye");
            address.setZipCode("34000");

            // 4. Sepet
            BasketItem item = new BasketItem();
            item.setId("BI101");
            item.setName("Bakiye Yükleme");
            item.setCategory1("Wallet");
            item.setItemType(BasketItemType.VIRTUAL.name());
            item.setPrice(topUpBalanceRequest.getAmount());

            List<BasketItem> items = List.of(item);

            // 5. Request Hazırlığı
            String conversationId = UUID.randomUUID().toString();

            CreatePaymentRequest request = new CreatePaymentRequest();
            request.setLocale(Locale.TR.getValue());
            request.setConversationId(conversationId);
            request.setPrice(topUpBalanceRequest.getAmount());
            request.setPaidPrice(topUpBalanceRequest.getAmount());
            request.setCurrency(Currency.TRY.name());
            request.setInstallment(1);
            request.setBasketId("B67832");
            request.setPaymentChannel(PaymentChannel.WEB.name());
            request.setPaymentGroup(PaymentGroup.PRODUCT.name());


            String baseUrl;
            System.out.println(topUpBalanceRequest.getPlatformType());
            if (topUpBalanceRequest.getPlatformType() == PlatformType.MOBILE) {
                baseUrl = "http://192.168.174.214:8080";
            } else if (topUpBalanceRequest.getPlatformType() == PlatformType.WEB) {
                baseUrl = "http://localhost:8080";
            } else {
                baseUrl = "http://localhost:8080";
            }

            request.setCallbackUrl(baseUrl + "/v1/api/wallet/payment/3d-callback");

            request.setConversationId(conversationId);

            request.setPaymentCard(paymentCard);
            request.setBuyer(buyer);
            request.setShippingAddress(address);
            request.setBillingAddress(address);
            request.setBasketItems(items);

            // 6. Iyzico 3D Başlat
            ThreedsInitialize threedsInitialize = ThreedsInitialize.create(request, options);

            if ("success".equals(threedsInitialize.getStatus())) {

                topUpSessionCache.put(conversationId,
                        new TopUpSessionData(username, topUpBalanceRequest.getAmount()));

                String htmlContent = threedsInitialize.getHtmlContent();
                return new DataResponseMessage<>("3D doğrulama başlatıldı. Yönlendirme yapılıyor.", true, htmlContent);
            } else {
                return new ResponseMessage("3D başlatma başarısız: " + threedsInitialize.getErrorMessage(), false);
            }

        } catch (Exception e) {
            return new ResponseMessage("3D başlatma hatası: " + e.getMessage(), false);
        }
    }


    @Override
    public ResponseMessage approveOrReject(ProcessIdentityRequest request, String username) throws UserNotFoundException, UnauthorizedAreaException, IdentityVerificationRequestNotFoundException, AlreadyWalletUserException {
        Optional<SecurityUser> securityUser = securityUserRepository.findByUserNumber(username);
        if (securityUser.isEmpty()) {
            throw new UserNotFoundException();
        }

        boolean isAuthorized = securityUser.get().getRoles().contains(Role.ADMIN) || securityUser.get().getRoles().contains(Role.SUPERADMIN);
        if (!isAuthorized) {
            throw new UnauthorizedAreaException();
        }


        IdentityVerificationRequest verificationRequest = identityVerificationRequestRepository
                .findById(request.getRequestId())
                .orElseThrow(IdentityVerificationRequestNotFoundException::new);

        if (verificationRequest.getStatus() != RequestStatus.PENDING) {
            return new ResponseMessage("Bu başvuru zaten " + verificationRequest.getStatus().name().toLowerCase() + ".", false);
        }

        verificationRequest.setReviewedBy(securityUser.get());
        verificationRequest.setReviewedAt(LocalDateTime.now());
        verificationRequest.setAdminNote(request.getAdminNote());
        UserIdentityInfo identityInfo = verificationRequest.getIdentityInfo();
        User user = identityInfo.getUser();

        if (request.isApproved()) {

            boolean walletCreated = false;
            try {
                walletCreated = createWalletForUser(user);
            } catch (Exception e) {

            }

            if (walletCreated) {
                verificationRequest.setStatus(RequestStatus.APPROVED);
                identityInfo.setApproved(true);
                identityInfo.setApprovedAt(LocalDateTime.now());
                identityInfo.setApprovedBy(securityUser.get());
                userIdentityInfoRepository.save(identityInfo);

                fcmService.sendNotificationToToken(
                        user,
                        "Kimlik Doğrulama Onayı",
                        "Kimlik doğrulama başvurunuz onaylandı. Artık cüzdanınızı kullanabilirsiniz.",
                        NotificationType.SUCCESS,
                        null
                );
            } else {
                throw new RuntimeException("Kullanıcıya cüzdan oluşturulamadığı için başvuru onaylanamadı.");
            }
        } else {
            verificationRequest.setStatus(RequestStatus.REJECTED);

            fcmService.sendNotificationToToken(
                    user,
                    "Kimlik Doğrulama Reddedildi",
                    "Kimlik doğrulama başvurunuz reddedildi. Not: " + request.getAdminNote(),
                    NotificationType.ALERT,
                    null
            );
        }

        identityVerificationRequestRepository.save(verificationRequest);

        return new ResponseMessage("Kimlik doğrulama başvurusu başarıyla " +
                (request.isApproved() ? "onaylandı." : "reddedildi."), true);
    }


    public boolean createWalletForUser(User user) throws AlreadyWalletUserException {
        if (user.getWallet() != null) {
            throw new AlreadyWalletUserException();
        }

        Wallet wallet = Wallet.builder()
                .user(user)
                .balance(BigDecimal.ZERO)
                .status(WalletStatus.ACTIVE)
                .currency("TRY")
                .build();
        walletRepository.save(wallet);

        return true;
    }

    @Override
    @Transactional
    public ResponseEntity<String> complete3DPayment(String paymentId, String conversationId) {
        log.info("3D Callback alındı - paymentId: {}, conversationId: {}", paymentId, conversationId);

        if (paymentId == null || paymentId.isEmpty() || conversationId == null || conversationId.isEmpty()) {
            log.warn("Callback parametreleri eksik! paymentId veya conversationId boş.");
            return ResponseEntity.badRequest().body("Eksik parametreler gönderildi.");
        }

        // İyzico'dan ödeme detayını sorgula
        RetrievePaymentRequest retrieveRequest = new RetrievePaymentRequest();
        retrieveRequest.setPaymentId(paymentId);
        retrieveRequest.setConversationId(conversationId);
        retrieveRequest.setLocale("tr");

        try {
            Payment payment = Payment.retrieve(retrieveRequest, iyzicoOptions);
            log.info("İyzico'dan dönen payment status: {}", payment.getStatus());

            if ("success".equalsIgnoreCase(payment.getStatus())) {
                TopUpSessionData sessionData = topUpSessionCache.get(conversationId);
                if (sessionData == null) {
                    log.warn("TopUpSessionCache içinde '{}' için veri bulunamadı", conversationId);
                    return ResponseEntity.badRequest().body("Kullanıcı bilgisi bulunamadı. Yükleme yapılamadı.");
                }

                // Kullanıcıyı bul
                User user = userRepository.findByUserNumber(sessionData.getUsername()).orElse(null);
                if (user == null) {
                    log.warn("TopUp işlemi için kullanıcı bulunamadı. username: {}", sessionData.getUsername());
                    return ResponseEntity.badRequest().body("Kullanıcı bulunamadı. Yükleme yapılamadı.");
                }

                // Cüzdana yükleme yap
                ResponseMessage result = handleSuccessfulTopUp(user, sessionData.getAmount(), payment.getPaymentId());
                log.info("Bakiye yükleme sonucu: {}", result.getMessage());

                // Cache temizle
                topUpSessionCache.remove(conversationId);

                return ResponseEntity.ok(result.getMessage());
            } else {
                return ResponseEntity.badRequest().body("3D ödeme başarısız: " + payment.getErrorMessage());
            }
        } catch (Exception e) {
            log.error("3D ödeme tamamlama sırasında hata: ", e);
            return ResponseEntity.internalServerError().body("Hata: " + e.getMessage());
        }
    }

    @Override
    public Wallet getWalletByUsername(String username) throws WalletNotActiveException, WalletNotFoundException, UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        Wallet wallet = user.getWallet();
        if (wallet == null) {
            throw new WalletNotFoundException();
        }
        if (wallet.getStatus() != WalletStatus.ACTIVE) {
            throw new WalletNotActiveException();
        }
        return wallet;

    }

    @Override
    public Page<WalletTransactionDTO> getOutgoingTransfers(Long walletId, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<WalletTransaction> outgoingTransfers =
                walletTransactionRepository.findByWalletIdAndType(walletId, TransactionType.TRANSFER_OUT, pageable);

        return outgoingTransfers.map(walletConverter::convertToTransactionDTO);
    }


    @Override
    public Page<WalletTransactionDTO> getIncomingTransfers(Long walletId, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<WalletTransaction> incomingTransfers = walletTransactionRepository.findByWalletIdAndType(walletId, TransactionType.TRANSFER_IN, pageable);

        return incomingTransfers.map(walletConverter::convertToTransactionDTO);
    }


    @Transactional
    public ResponseMessage handleSuccessfulTopUp(User user, BigDecimal amount, String iyzicoReference) throws WalletNotFoundException {

        Wallet wallet = walletRepository.findByUser(user)
                .orElseThrow(WalletNotFoundException::new);

        wallet.setBalance(wallet.getBalance().add(amount));
        wallet.setTotalTransactionCount(wallet.getTotalTransactionCount() + 1);
        wallet.setLastUpdated(LocalDateTime.now());

        WalletTransaction transaction = WalletTransaction.builder()
                .wallet(wallet)
                .amount(amount)
                .type(TransactionType.TRANSFER_IN)
                .status(TransactionStatus.SUCCESS)
                .timestamp(LocalDateTime.now())
                .description("İyzico ile bakiye yükleme")
                .externalReference(iyzicoReference)
                .userId(user.getId())
                .build();

        wallet.getTransactions().add(transaction);

        WalletActivity activity = WalletActivity.builder()
                .walletId(wallet.getId())
                .activityType(WalletActivityType.TRANSACTION)
                .transactionId(null)
                .activityDate(LocalDateTime.now())
                .description("Kullanıcı bakiyesine " + amount + " TL yüklendi.")
                .build();
        walletActivityRepository.save(activity);

        walletRepository.save(wallet);
        fcmService.sendNotificationToToken(
                user,
                "Bakiye Yükleme Başarılı",
                amount + " TL bakiyenize başarıyla yüklendi.",
                NotificationType.SUCCESS,
                null
        );
        return new ResponseMessage("Yükleme başarılı.", true);
    }


}
