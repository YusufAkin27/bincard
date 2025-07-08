package akin.city_card.wallet.service.concretes;

import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.repository.SecurityUserRepository;
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
import akin.city_card.wallet.core.request.ApproveIdentityRequest;
import akin.city_card.wallet.core.request.CreateWalletRequest;
import akin.city_card.wallet.core.request.TopUpBalanceRequest;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.core.response.WalletStatsDTO;
import akin.city_card.wallet.exceptions.AlreadyWalletUserException;
import akin.city_card.wallet.exceptions.IdentityVerificationRequestNotFoundException;
import akin.city_card.wallet.exceptions.WalletNotActiveException;
import akin.city_card.wallet.exceptions.WalletNotFoundException;
import akin.city_card.wallet.model.*;
import akin.city_card.wallet.repository.WalletActivityRepository;
import akin.city_card.wallet.repository.WalletRepository;
import akin.city_card.wallet.repository.WalletTransferRepository;
import akin.city_card.wallet.service.abstracts.WalletService;
import com.iyzipay.Options;
import com.iyzipay.model.*;
import com.iyzipay.model.Currency;
import com.iyzipay.model.Locale;
import com.iyzipay.request.CreatePaymentRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

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


    @Override
    public DataResponseMessage<BigDecimal> getWalletBalance(String phone) throws WalletNotFoundException, UserNotFoundException, WalletNotActiveException {
        User user=userRepository.findByUserNumber(phone);
        if (user==null) throw new UserNotFoundException();

        if (user.getWallet()==null) throw new WalletNotFoundException();

        if (!user.getWallet().getStatus().equals(WalletStatus.ACTIVE)) throw new WalletNotActiveException();
        return new DataResponseMessage <>("cüzdan bakiyesi",true,user.getWallet().getBalance());
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
    @Transactional
    public ResponseMessage createWallet(String phone, CreateWalletRequest request) throws UserNotFoundException, OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException, VideoSizeLargerException, FileFormatCouldNotException {
        User user = userRepository.findByUserNumber(phone);
        if (user == null) throw new UserNotFoundException();

        List<IdentityVerificationRequest> existingRequests = identityVerificationRequestRepository.findByRequestedBy(user);

        boolean hasPendingOrApproved = existingRequests.stream()
                .anyMatch(r -> r.getStatus() == RequestStatus.PENDING || r.getStatus() == RequestStatus.APPROVED);

        if (hasPendingOrApproved) {
            return new ResponseMessage("Kimlik doğrulama isteğiniz zaten işleniyor veya onaylanmış.", false);
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

        // Kimlik onay başvurusu oluştur
        IdentityVerificationRequest verificationRequest = IdentityVerificationRequest.builder()
                .identityInfo(identityInfo)
                .requestedBy(user) // User → SecurityUser ilişkisini kullan
                .requestedAt(LocalDateTime.now())
                .status(RequestStatus.PENDING)
                .build();
        identityVerificationRequestRepository.save(verificationRequest);


        return new ResponseMessage("Kimlik onay başvurusu alındı. ", true);
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

    @Override
    @Transactional
    public ResponseMessage topUp(String username, TopUpBalanceRequest topUpBalanceRequest) throws UserNotFoundException, WalletNotFoundException {
        User user = userRepository.findByUserNumber(username);
        if (user == null) {
            throw new UserNotFoundException();
        }

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
    public ResponseMessage approveOrReject(ApproveIdentityRequest request, String username) throws UserNotFoundException, UnauthorizedAreaException, IdentityVerificationRequestNotFoundException, AlreadyWalletUserException {
        Optional<SecurityUser> securityUser = securityUserRepository.findByUserNumber(username);
        if (securityUser.isEmpty()) {
            throw new UserNotFoundException();
        }
/*
        boolean isAdmin = securityUser.get().getRoles().contains("ADMIN");
        boolean isSuperAdmin = securityUser.get().getRoles().contains("SUPERADMIN");

        if (!isAdmin && !isSuperAdmin) {
            throw new UnauthorizedAreaException();
        }

 */

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

        // 4. Cüzdanı güncelle
        walletRepository.save(wallet);

        return new ResponseMessage("Yükleme başarılı.", true);
    }


}
