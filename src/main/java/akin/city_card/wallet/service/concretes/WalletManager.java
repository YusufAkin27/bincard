package akin.city_card.wallet.service.concretes;

import akin.city_card.bus.exceptions.UnauthorizedAccessException;
import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
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
import akin.city_card.user.model.IdentityVerificationRequest;
import akin.city_card.user.model.RequestStatus;
import akin.city_card.user.model.User;
import akin.city_card.user.model.UserIdentityInfo;
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
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;


@Service
@RequiredArgsConstructor
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
    private final UserConverter userConverter;


    @Override
    public DataResponseMessage<BigDecimal> getWalletBalance(String phone) throws WalletNotFoundException, UserNotFoundException, WalletNotActiveException {
        User user = userRepository.findByUserNumber(phone).orElseThrow(UserNotFoundException::new);;

        if (user.getWallet() == null) throw new WalletNotFoundException();

        if (!user.getWallet().getStatus().equals(WalletStatus.ACTIVE)) throw new WalletNotActiveException();
        return new DataResponseMessage<>("cüzdan bakiyesi", true, user.getWallet().getBalance());
    }

    private User findReceiverByIdentifier(String identifier) throws UserNotFoundException {
        if (identifier == null) return null;

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(identifier);
        if (PhoneNumberFormatter.PhoneValid(normalizedPhone)) {
            return userRepository.findByUserNumber(normalizedPhone).orElseThrow(UserNotFoundException::new);
        }

        if (identifier.startsWith("WBN-")) {
            Wallet wallet = walletRepository.findByWiban(identifier);
            return wallet != null ? wallet.getUser() : null;
        }

        if (identifier.contains("@")) {
            return userRepository.findByProfileInfo_Email(identifier);
        }

        if (identifier.matches("\\d{11}")) {
            return userRepository.findByIdentityInfo_NationalId(identifier);
        }

        return null;
    }

    @Override
    public ResponseMessage transfer(String senderPhone, WalletTransferRequest walletTransferRequest) throws UserNotFoundException, ReceiverNotFoundException, WalletNotFoundException, ReceiverWalletNotFoundException, WalletNotActiveException, ReceiverWalletNotActiveException, InsufficientFundsException {
        User sender = userRepository.findByUserNumber(PhoneNumberFormatter.normalizeTurkishPhoneNumber(senderPhone)).orElseThrow(UserNotFoundException::new);;
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
                .type(TransactionType.WITHDRAW)
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
                .type(TransactionType.DEPOSIT)
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

        String msg = String.format("transferId: %d\namount: %s\nsenderBalance: %s\nreceiverPhone: %s",
                savedTransfer.getId(), transferAmount, senderWallet.getBalance(), receiver.getUserNumber());

        return new ResponseMessage(msg, true);
    }


    @Override
    @Transactional
    public ResponseMessage toggleWalletStatus(String phone, boolean isActive) throws WalletNotFoundException, WalletNotActiveException, UserNotFoundException, WalletDeactivationException {

        User user = userRepository.findByUserNumber(phone).orElseThrow(UserNotFoundException::new);;

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

        String message = isActive ? "Cüzdan başarıyla aktifleştirildi." : "Cüzdan başarıyla askıya alındı.";
        return new ResponseMessage(message, true);
    }


    @Override
    public DataResponseMessage<Page<WalletActivityDTO>> getActivities(String username, WalletActivityType type, LocalDate start, LocalDate end, Pageable pageable) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {

        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);;


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
        User user = userRepository.findByUserNumber(phone).orElseThrow(UserNotFoundException::new);;

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
                .frontCardPhoto(mediaUploadService.uploadAndOptimizeMedia(request.getFrontCardPhoto()).join())
                .backCardPhoto(mediaUploadService.uploadAndOptimizeMedia(request.getBackCardPhoto()).join())
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
            if (tx.getType() == TransactionType.DEPOSIT) {
                runningBalance = runningBalance.add(tx.getAmount());
            } else if (tx.getType() == TransactionType.WITHDRAW) {
                runningBalance = runningBalance.subtract(tx.getAmount());
            }

            balanceHistory.add(BalanceHistoryDTO.builder()
                    .date(tx.getTimestamp())
                    .balance(runningBalance)
                    .build());
        }

        return new DataResponseMessage<>("bakiye geçmişi",true,balanceHistory);
    }


    @Override
    public ResponseMessage changeStatusAsAdmin(String username, String userNumber, boolean activate, String statusReason) {
        return null;
    }


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
                        List.of(TransactionType.DEPOSIT, TransactionType.WITHDRAW),
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

        // Tarih aralığı geçerliliği kontrolü
        if (startDate != null && endDate != null && endDate.isBefore(startDate)) {
            throw new IllegalArgumentException("Bitiş tarihi, başlangıç tarihinden önce olamaz.");
        }

        // Sıralama belirleme
        Sort sort = Sort.by(Sort.Direction.fromString(sortDir.toUpperCase()), sortBy);
        Pageable pageable = PageRequest.of(page, size, sort);

        // PostgreSQL uyumlu tarih aralıkları belirleme
        LocalDateTime defaultStart = LocalDateTime.of(1970, 1, 1, 0, 0);
        LocalDateTime defaultEnd = LocalDateTime.now().plusYears(1);

        LocalDateTime start = (startDate != null) ? startDate.atStartOfDay() : defaultStart;
        LocalDateTime end = (endDate != null)
                ? endDate.plusDays(1).atStartOfDay().minusNanos(1)
                : defaultEnd;

        // Veritabanı sorgusu
        Page<IdentityVerificationRequest> resultPage;
        if (status != null) {
            resultPage = identityVerificationRequestRepository
                    .findAllByStatusAndRequestedAtBetween(status, start, end, pageable);
        } else {
            resultPage = identityVerificationRequestRepository
                    .findAllByRequestedAtBetween(start, end, pageable);
        }

        // DTO dönüşümü
        Page<IdentityVerificationRequestDTO> dtoPage = resultPage.map(userConverter::convertToVerificationRequestDTO);

        return new DataResponseMessage<>(
                "Kimlik doğrulama başvuruları başarıyla getirildi.",
                true,
                dtoPage
        );
    }


    @Override
    public WalletDTO getMyWallet(String username) throws WalletNotFoundException, WalletNotActiveException, UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);;
        Wallet wallet = user.getWallet();
        if (wallet == null) throw new WalletNotFoundException();
        if (!wallet.getStatus().equals(WalletStatus.ACTIVE)) throw new WalletNotActiveException();
        return walletConverter.convertToDTO(wallet);
    }


    @Override
    @Transactional
    public ResponseMessage topUp(String username, TopUpBalanceRequest topUpBalanceRequest) throws UserNotFoundException, WalletNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);;


        if (!user.isActive()) {
            return new ResponseMessage("Kullanıcı hesabı aktif değil.", false);
        }

        Wallet wallet = user.getWallet();
        if (wallet == null) {
            throw new WalletNotFoundException();
        }

        if (!wallet.getStatus().equals(WalletStatus.ACTIVE)) {
            return new ResponseMessage("Cüzdan aktif değil. Durum: " + wallet.getStatus(), false);
        }

        if (topUpBalanceRequest.getAmount() == null || topUpBalanceRequest.getAmount().compareTo(BigDecimal.ONE) < 0) {
            return new ResponseMessage("Yükleme tutarı en az 1 TL olmalıdır.", false);
        }
        LocalDateTime lastLogin = user.getLoginHistory().isEmpty() ? null : user.getLoginHistory().get(0).getLoginAt();

        try {
            Options options = iyzicoOptions;

            PaymentCard paymentCard = new PaymentCard();
            paymentCard.setCardHolderName(username); // kullanıcı adı burada yer alabilir
            paymentCard.setCardNumber(topUpBalanceRequest.getCardNumber());
            paymentCard.setExpireMonth(topUpBalanceRequest.getCardExpiry().split("/")[0].trim());
            paymentCard.setExpireYear("20" + topUpBalanceRequest.getCardExpiry().split("/")[1].trim()); // örn: "24" → "2024"
            paymentCard.setCvc(topUpBalanceRequest.getCardCvc());
            paymentCard.setRegisterCard(0); // kartı kaydetme

            Buyer buyer = new Buyer();
            buyer.setId("BY789");
            buyer.setName(user.getProfileInfo().getName());
            buyer.setSurname(user.getProfileInfo().getSurname());
            buyer.setGsmNumber(user.getUserNumber());
            buyer.setEmail(Optional.ofNullable(user.getProfileInfo().getEmail()).orElse("default@mail.com"));
            buyer.setIdentityNumber(user.getIdentityInfo().getNationalId());
            assert lastLogin != null;
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            String formattedLastLogin = lastLogin.format(formatter);

            buyer.setLastLoginDate(formattedLastLogin);
            String formattedDate = user.getCreatedAt().format(formatter);

            buyer.setRegistrationDate(formattedDate);

            buyer.setRegistrationAddress("Türkiye");
            buyer.setIp(user.getDeviceInfo().getIpAddress());
            buyer.setCity("İstanbul");
            buyer.setCountry("Turkey");
            buyer.setZipCode("34000");

            // 4. Adres bilgisi
            Address address = new Address();
            address.setContactName(username);
            address.setCity("İstanbul");
            address.setCountry("Turkey");
            address.setAddress("Türkiye");
            address.setZipCode("34000");

            // 5. Sepet içeriği (zorunlu)
            BasketItem item = new BasketItem();
            item.setId("BI101");
            item.setName("Bakiye Yükleme");
            item.setCategory1("Wallet");
            item.setItemType(BasketItemType.VIRTUAL.name());
            item.setPrice(topUpBalanceRequest.getAmount());

            List<BasketItem> items = new ArrayList<>();
            items.add(item);

            // 6. Ödeme isteği
            CreatePaymentRequest request = new CreatePaymentRequest();
            request.setLocale(Locale.TR.getValue());
            request.setConversationId(UUID.randomUUID().toString());
            request.setPrice(topUpBalanceRequest.getAmount());
            request.setPaidPrice(topUpBalanceRequest.getAmount());
            request.setCurrency(Currency.TRY.name());
            request.setInstallment(1);
            request.setBasketId("B67832");
            request.setPaymentChannel(PaymentChannel.WEB.name());
            request.setPaymentGroup(PaymentGroup.PRODUCT.name());

            request.setPaymentCard(paymentCard);
            request.setBuyer(buyer);
            request.setShippingAddress(address);
            request.setBillingAddress(address);
            request.setBasketItems(items);

            Payment payment = Payment.create(request, options);

            if (payment.getStatus().equals("success")) {
                handleSuccessfulTopUp(user, topUpBalanceRequest.getAmount(), payment.getPaymentId());
                return new ResponseMessage("Ödeme başarılı, bakiye yüklendi.", true);
            } else {
                return new ResponseMessage("Ödeme başarısız: " + payment.getErrorMessage(), false);
            }

        } catch (Exception e) {
            return new ResponseMessage("Hata oluştu: " + e.getMessage(), false);
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


        // 3. Başvuruyu getir
        IdentityVerificationRequest verificationRequest = identityVerificationRequestRepository
                .findById(request.getRequestId())
                .orElseThrow(IdentityVerificationRequestNotFoundException::new);

        // 4. Zaten işlenmiş mi?
        if (verificationRequest.getStatus() != RequestStatus.PENDING) {
            return new ResponseMessage("Bu başvuru zaten " + verificationRequest.getStatus().name().toLowerCase() + ".", false);
        }

        // 5. Admin notu ve zaman bilgisi kaydet
        verificationRequest.setReviewedBy(securityUser.get());
        verificationRequest.setReviewedAt(LocalDateTime.now());
        verificationRequest.setAdminNote(request.getAdminNote());

        if (request.isApproved()) {
            UserIdentityInfo identityInfo = verificationRequest.getIdentityInfo();
            User user = identityInfo.getUser();

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
            } else {
                throw new RuntimeException("Kullanıcıya cüzdan oluşturulamadığı için başvuru onaylanamadı.");
            }
        } else {
            verificationRequest.setStatus(RequestStatus.REJECTED);
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
                .type(TransactionType.DEPOSIT)
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

        // 4. Cüzdanı güncelle
        walletRepository.save(wallet);

        return new ResponseMessage("Yükleme başarılı.", true);
    }


}
