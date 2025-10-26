package akin.city_card.buscard.service.concretes;


import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.ActionType;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.model.AuditLog;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.admin.repository.AuditLogRepository;
import akin.city_card.bus.exceptions.InsufficientBalanceException;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusRide;
import akin.city_card.bus.model.RideStatus;
import akin.city_card.bus.repository.BusRepository;
import akin.city_card.bus.repository.BusRideRepository;
import akin.city_card.buscard.core.converter.BusCardConverter;
import akin.city_card.buscard.core.request.*;
import akin.city_card.buscard.core.response.BusCardDTO;
import akin.city_card.buscard.core.response.CardPricingDTO;
import akin.city_card.buscard.exceptions.*;
import akin.city_card.buscard.model.*;
import akin.city_card.buscard.repository.ActivityRepository;
import akin.city_card.buscard.repository.BusCardRepository;
import akin.city_card.buscard.repository.CardPricingRepository;
import akin.city_card.buscard.repository.QRTokenRepository;
import akin.city_card.buscard.service.abstracts.BusCardService;
import akin.city_card.geoIpService.GeoIpService;
import akin.city_card.geoIpService.GeoLocationData;
import akin.city_card.news.model.PlatformType;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.service.FCMService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.service.concretes.UserManager;
import akin.city_card.wallet.core.request.TopUpBalanceRequest;
import akin.city_card.wallet.core.response.TopUpSessionData;
import akin.city_card.wallet.exceptions.WalletNotActiveException;
import akin.city_card.wallet.exceptions.WalletNotFoundException;
import akin.city_card.wallet.model.*;
import akin.city_card.wallet.repository.WalletActivityRepository;
import akin.city_card.wallet.repository.WalletRepository;
import akin.city_card.wallet.service.concretes.TopUpSessionCache;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.iyzipay.Options;
import com.iyzipay.model.*;
import com.iyzipay.model.Currency;
import com.iyzipay.model.Locale;
import com.iyzipay.request.CreatePaymentRequest;
import com.iyzipay.request.DeleteCardRequest;
import com.iyzipay.request.RetrievePaymentRequest;
import io.craftgate.request.UpdateCardRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class BusCardManager implements BusCardService {
    private final ObjectMapper objectMapper;
    private final Options iyzicoOptions;
    private final BusCardRepository busCardRepository;
    private final CardPricingRepository cardPricingRepository;
    private final UserRepository userRepository;
    private final AdminRepository adminRepository;
    private final WalletRepository walletRepository;
    private final BusCardConverter busCardConverter;
    private final AuditLogRepository auditLogRepository;
    private final ActivityRepository activityRepository;
    private final TopUpSessionCache topUpSessionCache;
    private final BusRepository busRepository;
    private final QRTokenRepository qrTokenRepository;
    private final WalletActivityRepository walletActivityRepository;
    private final FCMService fcmService;
    private final BusRideRepository busRideRepository;
    private final GeoIpService geoIpService;
    private final UserManager userManager;


    @Override
    @Transactional
    public BusCardDTO registerCard(HttpServletRequest httpServletRequest, RegisterCardRequest req, String username) throws AlreadyBusCardNumberException {
        Admin admin = adminRepository.findByUserNumber(username);
        createAuditLog(admin, ActionType.NEW_CARD_REGISTRATION, "Yeni kart kaydedildi", admin.getCurrentDeviceInfo(), admin.getId(), admin.getRoles().toString(), null, null, null);

        if (busCardRepository.existsByCardNumber(req.getUid())) {
            throw new AlreadyBusCardNumberException();

        }
        BusCard busCard = busCardConverter.registerCard(req);
        busCardRepository.save(busCard);
        return busCardConverter.BusCardToBusCardDTO(busCard);
    }

    @Override
    public BusCardDTO readCard(String reqUid, String username) throws BusCardNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        createAuditLog(admin, ActionType.READ_CARD, "Kart okundu", admin.getCurrentDeviceInfo(), admin.getId(), admin.getRoles().toString(), null, null, null);

        return busCardConverter.BusCardToBusCardDTO(busCardRepository.findByCardNumber(reqUid).orElseThrow(BusCardNotFoundException::new));
    }


    @Override
    @Transactional
    public BusCardDTO getOn(GetOnBusRequest request) throws BusCardNotFoundException, CardInactiveException, CardPricingNotFoundException, CorruptedDataException, SubscriptionNotFoundException, SubscriptionExpiredException, InsufficientBalanceException {

        String uid = request.getUid();
        String validatorId = request.getValidatorId();

        BusCard busCard = busCardRepository.findByCardNumber(uid)
                .orElseThrow(BusCardNotFoundException::new);

        if (!busCard.isActive() || busCard.getStatus() != CardStatus.ACTIVE) {
            throw new CardInactiveException();
        }

        CardPricing pricing = cardPricingRepository.findByCardType(busCard.getType())
                .orElseThrow(CardPricingNotFoundException::new);

        if (busCard.getTxCounter() == null || busCard.getTxCounter() < 0) {
            throw new CorruptedDataException();
        }

        BusCardActivity lastBusCardActivity = getLastActivity(busCard);
        LocalDateTime now = LocalDateTime.now();

        boolean isTransfer = false;
        boolean sameValidator = false;

        if (lastBusCardActivity != null) {
            long minutesSinceLast = java.time.Duration.between(lastBusCardActivity.getUseDateTime(), now).toMinutes();

            if (minutesSinceLast <= 45) {
                if (lastBusCardActivity.getValidatorId().equals(validatorId)) {
                    sameValidator = true;
                } else {
                    isTransfer = true;
                }
            }
        }

        if (busCard.getSubscriptionInfo() != null) {
            SubscriptionInfo sub = busCard.getSubscriptionInfo();

            if (sub == null) throw new SubscriptionNotFoundException();

            if (sub.getEndDate() != null && sub.getEndDate().isBefore(LocalDate.now())) {
                busCard.setSubscriptionInfo(null);
            }

            if (sub.getRemainingUses() <= 0) {
                busCard.setSubscriptionInfo(null);
            }

            sub.setRemainingUses(sub.getRemainingUses() - 1);
            busCard.setTxCounter(busCard.getTxCounter() + 1);

            BusCardActivity busCardActivity = createActivity(busCard, request, BigDecimal.ZERO, false, now);
            activityRepository.save(busCardActivity);

            busCard.getActivities().add(busCardActivity);
            busCardRepository.save(busCard);

            return busCardConverter.BusCardToBusCardDTO(busCard);
        }


        BigDecimal fare;

        if (sameValidator) {
            fare = pricing.getPrice();
            isTransfer = false;

        } else if (isTransfer) {
            CardType transferType = switch (busCard.getType()) {
                case TAM -> CardType.TAM_AKTARMA;
                case ÖĞRENCİ -> CardType.ÖĞRENCİ_AKTARMA;
                default -> null;
            };

            if (transferType != null) {
                CardPricing transferPricing = cardPricingRepository.findByCardType(transferType)
                        .orElseThrow(CardPricingNotFoundException::new);
                fare = transferPricing.getPrice();
            } else {
                fare = pricing.getPrice();
            }

        } else {
            fare = pricing.getPrice();
        }

        if (busCard.getBalance().compareTo(fare) < 0) {
            throw new InsufficientBalanceException();
        }

        busCard.setBalance(busCard.getBalance().subtract(fare));
        busCard.setLastTransactionAmount(fare);
        busCard.setLastTransactionDate(LocalDate.now());
        busCard.setTxCounter(busCard.getTxCounter() + 1);

        BusCardActivity busCardActivity = createActivity(busCard, request, fare, isTransfer, now);
        activityRepository.save(busCardActivity);
        busCard.getActivities().add(busCardActivity);


        Bus bus = busRepository.findByValidatorId(validatorId).orElseThrow(BusCardNotFoundException::new);
        BusRide busRide = new BusRide();
        busRide.setBus(bus);
        busRide.setBusCard(busCard);
        busRide.setStatus(RideStatus.SUCCESS);
        busRide.setBoardingTime(LocalDateTime.now());
        busRide.setFareCharged(fare);
        bus.getRides().add(busRide);
        busCardRepository.save(busCard);
        busRideRepository.save(busRide);

        busCardRepository.save(busCard);

        return busCardConverter.BusCardToBusCardDTO(busCard);
    }

    private BusCardActivity getLastActivity(BusCard card) {
        if (card.getActivities() == null || card.getActivities().isEmpty())
            return null;
        return card.getActivities()
                .stream()
                .max(Comparator.comparing(BusCardActivity::getUseDateTime))
                .orElse(null);
    }

    private BusCardActivity createActivity(BusCard busCard, GetOnBusRequest request,
                                           BigDecimal price, boolean isTransfer, LocalDateTime time) {

        BusCardActivity busCardActivity = new BusCardActivity();
        busCardActivity.setBusCard(busCard);
        busCardActivity.setUseDateTime(time);
        busCardActivity.setPrice(price);
        busCardActivity.setValidatorId(request.getValidatorId());
        busCardActivity.setTransfer(isTransfer);
        return busCardActivity;
    }


    @Override
    @Transactional
    public ResponseMessage createCardPricing(CreateCardPricingRequest createCardPricingRequest, String username) throws AdminNotFoundException {
        Admin yusuf = adminRepository.findByUserNumber(username);
        if (yusuf == null) {
            throw new AdminNotFoundException();
        }
        CardPricing cardPricing = new CardPricing();
        cardPricing.setCardType(createCardPricingRequest.getCardType());
        cardPricing.setPrice(createCardPricingRequest.getPrice());
        cardPricing.setCreatedAt(LocalDateTime.now());
        cardPricing.setUpdatedAt(LocalDateTime.now());
        cardPricingRepository.save(cardPricing);
        return new ResponseMessage("Kart fiyatlandırma başarılı", true);
    }

    @Override
    @Transactional
    public BusCardDTO cardVisa(ReadCardRequest request, String username)
            throws BusCardNotFoundException, AdminNotFoundException,
            BusCardNotStudentException, BusCardNotActiveException {

        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null) {
            throw new AdminNotFoundException();
        }

        BusCard busCard = busCardRepository.findByCardNumber(request.getUid())
                .orElseThrow(BusCardNotFoundException::new);

        if (!busCard.getStatus().equals(CardStatus.ACTIVE) || !busCard.isActive()) {
            throw new BusCardNotActiveException();
        }

        if (!busCard.getType().equals(CardType.ÖĞRENCİ)) {
            throw new BusCardNotStudentException();
        }

        busCard.setVisaCompleted(true);
        busCard.setExpiryDate(LocalDate.now().plusYears(1));
        busCard.setLastTransactionDate(LocalDate.now());
        busCard.setLastTransactionAmount(BigDecimal.ZERO);
        busCard.setTxCounter(0);

        busCardRepository.save(busCard);

        return busCardConverter.BusCardToBusCardDTO(busCard);
    }


    @Override
    @Transactional
    public BusCardDTO cardBlocked(ReadCardRequest request, String username) throws AdminNotFoundException, BusCardNotActiveException, BusCardNotFoundException, BusCardAlreadyIsBlockedException {
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null) throw new AdminNotFoundException();

        BusCard busCard = busCardRepository.findByCardNumber(request.getUid()).orElseThrow(BusCardNotFoundException::new);
        if (!busCard.isActive()) throw new BusCardNotActiveException();
        if (busCard.getStatus().equals(CardStatus.BLOCKED)) throw new BusCardAlreadyIsBlockedException();

        createAuditLog(admin, ActionType.CARD_BLOCKED, "Kart bloklandı: " + request.getUid(),
                admin.getCurrentDeviceInfo(), busCard.getId(), "BusCard", null,
                "Kart numarası: " + request.getUid(), null);

        busCard.setStatus(CardStatus.BLOCKED);
        BusCard savedBusCard = busCardRepository.save(busCard);

        return busCardConverter.BusCardToBusCardDTO(savedBusCard);
    }


    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp.trim();
        }

        return request.getRemoteAddr();
    }

    public DeviceInfo buildDeviceInfoFromRequest(HttpServletRequest httpRequest, GeoIpService geoIpService) {
        String ipAddress = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        String deviceType = "Unknown";
        if (userAgent != null) {
            String uaLower = userAgent.toLowerCase();
            if (uaLower.contains("mobile")) deviceType = "Mobile";
            else if (uaLower.contains("tablet")) deviceType = "Tablet";
            else deviceType = "Desktop";
        }

        GeoLocationData geoData = geoIpService.getGeoData(ipAddress);
        return DeviceInfo.builder()
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .deviceType(deviceType)
                .city(Optional.ofNullable(geoData).map(GeoLocationData::getCity).orElse(null))
                .region(Optional.ofNullable(geoData).map(GeoLocationData::getRegion).orElse(null))
                .timezone(Optional.ofNullable(geoData).map(GeoLocationData::getTimezone).orElse(null))
                .org(Optional.ofNullable(geoData).map(GeoLocationData::getOrg).orElse(null))
                .build();
    }

    public void updateDeviceInfoAndCreateAuditLog(
            SecurityUser user,
            HttpServletRequest httpRequest,
            GeoIpService geoIpService,
            ActionType action,
            String description,
            Double amount,
            String metadata
    ) {
        DeviceInfo deviceInfo = buildDeviceInfoFromRequest(httpRequest, geoIpService);

        String referer = httpRequest.getHeader("Referer");
        String fullMetadata = (metadata == null ? "" : metadata + ", ") + (referer != null ? "Referer: " + referer : "");

        user.setCurrentDeviceInfo(deviceInfo);

        createAuditLog(
                user,
                action,
                description,
                deviceInfo,
                user.getId(),
                user.getRoles().toString(),
                amount,
                fullMetadata,
                referer

        );
    }

    public void createAuditLog(SecurityUser user,
                               ActionType action,
                               String description,
                               DeviceInfo deviceInfo,
                               Long targetEntityId,
                               String targetEntityType,
                               Double amount,
                               String metadata,
                               String referer) {

        AuditLog auditLog = new AuditLog();
        auditLog.setUser(user);
        auditLog.setAction(action);
        auditLog.setDescription(description);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLog.setDeviceInfo(deviceInfo);
        auditLog.setTargetEntityId(targetEntityId);
        auditLog.setTargetEntityType(targetEntityType);
        auditLog.setAmount(amount);
        auditLog.setMetadata(metadata);
        auditLog.setReferer(referer);

        auditLogRepository.save(auditLog);
    }

    public void createAuditLog(Admin admin,
                               ActionType action,
                               String description,
                               DeviceInfo deviceInfo,
                               Long targetEntityId,
                               String targetEntityType,
                               Double amount,
                               String metadata,
                               String referer) {

        AuditLog auditLog = new AuditLog();
        auditLog.setAdmin(admin);
        auditLog.setAction(action);
        auditLog.setDescription(description);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLog.setDeviceInfo(deviceInfo);
        auditLog.setTargetEntityId(targetEntityId);
        auditLog.setTargetEntityType(targetEntityType);
        auditLog.setAmount(amount);
        auditLog.setMetadata(metadata);
        auditLog.setReferer(referer);

        auditLogRepository.save(auditLog);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public byte[] generateQrCode(String username)
            throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException,
            CardPricingNotFoundException, InsufficientBalanceException {

        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);
        Wallet wallet = walletRepository.findByUser(user)
                .orElseThrow(WalletNotFoundException::new);
        CardPricing cardPricing = cardPricingRepository.findByCardType(CardType.TAM)
                .orElseThrow(CardPricingNotFoundException::new);

        if (!WalletStatus.ACTIVE.equals(wallet.getStatus())) {
            throw new WalletNotActiveException();
        }
        if (wallet.getBalance().compareTo(cardPricing.getPrice()) < 0) {
            throw new InsufficientBalanceException();
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(300);
        String nonce = UUID.randomUUID().toString();

        Map<String, Object> payload = new HashMap<>();
        payload.put("v", 1);
        payload.put("userNumber", user.getUsername());
        payload.put("walletId", wallet.getWiban());
        payload.put("price", cardPricing.getPrice());
        payload.put("issuedAt", issuedAt.toEpochMilli());
        payload.put("expiresAt", expiresAt.toEpochMilli());
        payload.put("nonce", nonce);

        try {
            String json = objectMapper.writeValueAsString(payload);

            String secret = "8de51002adb5ed3faf17076a91d4bbb98ffdd5be3c98812ed15c5f82e2f80e03";
            String signature = hmacSha256(json, secret);

            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(json.getBytes(StandardCharsets.UTF_8));
            String token = encodedPayload + "." + signature;

            QrToken qr = new QrToken();
            qr.setToken(token);
            qr.setUserNumber(user.getUsername());
            qr.setIssuedAt(issuedAt);
            qr.setExpiresAt(expiresAt);
            qr.setUsed(false);
            qrTokenRepository.save(qr);

            return generateQrImageBytes(token, 400, 400);

        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("Unable to create signed QR", ex);
        }
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public ResponseMessage verifyQrToken(String qrToken)
            throws InvalidQrCodeException, ExpiredQrCodeException,
            UserNotFoundException, WalletNotFoundException,
            InsufficientBalanceException, WalletNotActiveException, CardPricingNotFoundException {

        if (!qrStatus(qrToken)) {
            throw new InvalidQrCodeException();
        }

        String[] parts = qrToken.split("\\.");
        if (parts.length != 2) {
            throw new InvalidQrCodeException();
        }

        String encodedPayload = parts[0];
        String providedSignature = parts[1];

        final String json;
        try {
            json = new String(Base64.getUrlDecoder().decode(encodedPayload), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new InvalidQrCodeException();
        }

        String secret = "8de51002adb5ed3faf17076a91d4bbb98ffdd5be3c98812ed15c5f82e2f80e03";
        String expectedSignature = hmacSha256(json, secret);
        if (!expectedSignature.equals(providedSignature)) {
            throw new InvalidQrCodeException();
        }

        Map<String, Object> payload;
        try {
            payload = objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {
            });
        } catch (IOException e) {
            throw new InvalidQrCodeException();
        }

        String userNumber = (String) payload.get("userNumber");
        long expiresAtMs = Long.parseLong(payload.get("expiresAt").toString());

        QrToken qr = qrTokenRepository.findByTokenForUpdate(qrToken)
                .orElseThrow(InvalidQrCodeException::new);

        Instant now = Instant.now();
        if (qr.isUsed()) {
            throw new InvalidQrCodeException();
        }
        if (qr.getExpiresAt().isBefore(now) || now.toEpochMilli() > expiresAtMs) {
            throw new ExpiredQrCodeException();
        }

        User user = userRepository.findByUserNumber(userNumber)
                .orElseThrow(UserNotFoundException::new);

        Wallet wallet = walletRepository.findByUser(user)
                .orElseThrow(WalletNotFoundException::new);

        if (!WalletStatus.ACTIVE.equals(wallet.getStatus())) {
            throw new WalletNotActiveException();
        }

        CardPricing qrPricing = cardPricingRepository.findByCardType(CardType.QR_ÖDEME)
                .orElseThrow(CardPricingNotFoundException::new);

        BigDecimal qrPrice = qrPricing.getPrice();
        if (wallet.getBalance().compareTo(qrPrice) < 0) {
            throw new InsufficientBalanceException();
        }

        WalletActivity activity = WalletActivity.builder()
                .walletId(wallet.getId())
                .wallet(wallet)
                .activityType(WalletActivityType.QR_PAYMENT)
                .activityDate(LocalDateTime.now())
                .description("QR ile ödeme işlemi gerçekleştirildi. Tutar: " + qrPrice + "₺")
                .build();

        wallet.getActivities().add(activity);
        walletActivityRepository.save(activity);

        wallet.setBalance(wallet.getBalance().subtract(qrPrice));
        walletRepository.save(wallet);

        qr.setUsed(true);
        qrTokenRepository.save(qr);

        return new ResponseMessage(
                "QR doğrulandı, " + qrPrice + "₺ düşüldü. Güncel bakiye: " + wallet.getBalance(),
                true
        );
    }


    private String hmacSha256(String json, String secret) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secretKeySpec = new javax.crypto.spec.SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hash = mac.doFinal(json.getBytes(StandardCharsets.UTF_8));
            String result = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            return result != null ? result : "fallback_signature";
        } catch (Exception e) {
            return "fallback_signature";
        }
    }

    @Override
    public List<CardPricingDTO> getAllCardPricing() {
        return cardPricingRepository.findAll().stream().map(busCardConverter::cardPricingToDTO).toList();
    }

    @Override
    @Transactional
    public ResponseMessage updateCardPricing(String username, UpdateCardPricingRequest updateCardPricingRequest)
            throws AdminNotFoundException, CardPricingNotFoundException {

        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null) {
            throw new AdminNotFoundException();
        }

        CardPricing cardPricing = cardPricingRepository.findByCardType(updateCardPricingRequest.getCardType()).orElseThrow(CardPricingNotFoundException::new);
        cardPricing.setPrice(updateCardPricingRequest.getPrice());
        cardPricing.setUpdatedAt(LocalDateTime.now());
        return new ResponseMessage("Kart fiyatı güncellendi", true);
    }

    @Override
    @Transactional
    public BusCardDTO deleteCardBlocked(ReadCardRequest request, String username) throws BusCardNotFoundException, AdminNotFoundException, BusCardNotActiveException, BusCardAlreadyIsBlockedException, BusCardNotBlockedException {
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null) {
            throw new AdminNotFoundException();
        }

        BusCard busCard = busCardRepository.findByCardNumber(request.getUid()).orElseThrow(BusCardNotFoundException::new);
        if (!busCard.isActive()) throw new BusCardNotActiveException();
        if (!busCard.getStatus().equals(CardStatus.BLOCKED)) throw new BusCardNotBlockedException();

        createAuditLog(admin, ActionType.CARD_UNBLOCKED, "Kart blokajı kaldırıldı: " + request.getUid(),
                admin.getCurrentDeviceInfo(), busCard.getId(), "BusCard", null,
                "Kart numarası: " + request.getUid(), null);

        busCard.setStatus(CardStatus.ACTIVE);
        BusCard savedBusCard = busCardRepository.save(busCard);

        return busCardConverter.BusCardToBusCardDTO(savedBusCard);
    }

    @Override
    public List<BusCardDTO> getBlockedCards(String username) {
        return busCardRepository.findAll().stream().filter(busCard -> busCard.getStatus().equals(CardStatus.BLOCKED)).filter(BusCard::isActive).map(busCardConverter::BusCardToBusCardDTO).toList();

    }

    @Override
    @Transactional
    public BusCardDTO topUpBalance(String username, TopUpBalanceCardRequest request)
            throws BusCardNotFoundException, BusCardNotActiveException, TransactionCounterException {

        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null) {
            throw new IllegalArgumentException("Admin not found for username: " + username);
        }

        BusCard busCard = busCardRepository.findByCardNumber(request.getUid())
                .orElseThrow(BusCardNotFoundException::new);

        if (!busCard.getStatus().equals(CardStatus.ACTIVE) || !busCard.isActive()) {
            throw new BusCardNotActiveException();
        }

        if (!busCard.getTxCounter().equals(request.getTsxCounter())) {
            throw new TransactionCounterException();
        }

        BigDecimal oldBalance = busCard.getBalance() != null ? busCard.getBalance() : BigDecimal.ZERO;
        BigDecimal newBalance = oldBalance.add(request.getAmount());
        busCard.setBalance(newBalance);

        busCard.setLastTransactionAmount(request.getAmount());
        busCard.setLastTransactionDate(LocalDate.now());
        busCard.setTxCounter(busCard.getTxCounter() + 1);

        busCardRepository.save(busCard);

        return busCardConverter.BusCardToBusCardDTO(busCard);
    }

    @Override
    public BusCardDTO editCard(String username, UpdateCardRequest updateCardRequest) {
        return null;
    }

    @Override
    public ResponseMessage deleteCard(String username, DeleteCardRequest deleteCardRequest) {
        return null;
    }

    @Override
    @Transactional
    public BusCardDTO abonmanOluştur(CreateSubscriptionRequest createSubscriptionRequest, String username) throws BusCardNotFoundException, AdminNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null) {
            throw new AdminNotFoundException();
        }

        BusCard busCard = busCardRepository.findByCardNumber(createSubscriptionRequest.getUid())
                .orElseThrow(BusCardNotFoundException::new);

        // Abonman bilgilerini oluştur
        SubscriptionInfo subscriptionInfo = new SubscriptionInfo();
        subscriptionInfo.setType(createSubscriptionRequest.getType());
        subscriptionInfo.setLoaded(createSubscriptionRequest.getLoaded());
        subscriptionInfo.setStartDate(createSubscriptionRequest.getStartDate() != null ?
                createSubscriptionRequest.getStartDate() : LocalDate.now());
        subscriptionInfo.setEndDate(createSubscriptionRequest.getEndDate() != null ?
                createSubscriptionRequest.getEndDate() : LocalDate.now().plusDays(30));
        subscriptionInfo.setRemainingUses(createSubscriptionRequest.getRemainingUses());
        subscriptionInfo.setRemainingDays(createSubscriptionRequest.getRemainingDays());

        // Kartı abonman kartına dönüştür
        busCard.setSubscriptionInfo(subscriptionInfo);
        busCard.setType(CardType.TAM); // Abonman kartı genellikle tam kart olur

        // Audit log oluştur
        createAuditLog(admin, ActionType.BUS_CARD_TOP_UP, "Abonman oluşturuldu: " + createSubscriptionRequest.getUid(),
                admin.getCurrentDeviceInfo(), busCard.getId(), "BusCard", null,
                "Abonman tipi: " + createSubscriptionRequest.getType(), null);

        BusCard savedBusCard = busCardRepository.save(busCard);

        return busCardConverter.BusCardToBusCardDTO(savedBusCard);
    }

    @Override
    public List<BusCardDTO> getAllCards(String username) {
        return List.of();
    }

    @Override
    public boolean qrStatus(String token) {
        QrToken qr = qrTokenRepository.findByToken(token)
                .orElse(null);
        if (qr == null) return false;
        if (qr.isUsed()) return false;
        if (qr.getExpiresAt().isBefore(Instant.now())) return false;
        return true;
    }

    @Override
    @Transactional
    public ResponseEntity<String> complete3DPayment(String paymentId, String conversationId,HttpServletRequest httpServletRequest) {
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
                    return ResponseEntity.badRequest().body("Yükleme oturum bilgisi bulunamadı.");
                }

                String username = sessionData.getUsername();
                String cardNumber = sessionData.getCardNumber();
                BigDecimal amount = sessionData.getAmount();

                log.info("Yükleme işlemi bilgileri -> Kullanıcı: {}, Kart: {}, Tutar: {}",
                        username, cardNumber, amount);

                // Kullanıcı doğrulaması
                User user = userRepository.findByUserNumber(username).orElse(null);
                if (user == null) {
                    log.warn("TopUp işlemi için kullanıcı bulunamadı. username: {}", username);
                    return ResponseEntity.badRequest().body("Kullanıcı bulunamadı. Yükleme yapılamadı.");
                }

                // BusCard'ı bul
                BusCard busCard = busCardRepository.findByCardNumber(cardNumber)
                        .orElse(null);
                if (busCard == null) {
                    log.warn("BusCard bulunamadı. cardNumber: {}", cardNumber);
                    return ResponseEntity.badRequest().body("Kart bulunamadı. Yükleme yapılamadı.");
                }

                // Kart durumu kontrolü
                if (!busCard.getStatus().equals(CardStatus.ACTIVE)) {
                    log.warn("Kart aktif değil: {}", cardNumber);
                    return ResponseEntity.badRequest().body("Kart aktif değil, işlem yapılamaz.");
                }
                if (busCard.getStatus().equals(CardStatus.BLOCKED)) {
                    log.warn("Kart bloke: {}", cardNumber);
                    return ResponseEntity.badRequest().body("Kart bloke edilmiş, işlem yapılamaz.");
                }

                handleSuccessfulTopUp(user,amount,paymentId,cardNumber,httpServletRequest);

                topUpSessionCache.remove(conversationId);

                return ResponseEntity.ok("");

            } else {
                log.warn("3D ödeme başarısız: {}", payment.getErrorMessage());
                return ResponseEntity.badRequest().body("3D ödeme başarısız: " + payment.getErrorMessage());
            }

        } catch (Exception e) {
            log.error("3D ödeme tamamlama sırasında hata:", e);
            return ResponseEntity.internalServerError().body("Hata: " + e.getMessage());
        }
    }


    @Override
    @Transactional
    public ResponseMessage topUp(String username, String cardNumber, TopUpBalanceRequest topUpBalanceRequest) throws BusCardNotFoundException, BusCardNotActiveException, BusCardIsBlockedException, MinumumTopUpAmountException, UserNotFoundException {

        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        if (!user.isEnabled()) {
            return new ResponseMessage("Kullanıcı hesabı aktif değil.", false);
        }

        if (topUpBalanceRequest.getAmount() == null
                || topUpBalanceRequest.getAmount().compareTo(BigDecimal.valueOf(20)) < 0) {
            throw new MinumumTopUpAmountException();
        }
        BusCard busCard = busCardRepository.findByCardNumber(cardNumber).orElseThrow(BusCardNotFoundException::new);


        if (!busCard.getStatus().equals(CardStatus.ACTIVE)) throw new BusCardNotActiveException();
        if(busCard.getStatus().equals(CardStatus.BLOCKED)) throw new BusCardIsBlockedException();

        try {
            Options options = iyzicoOptions;

            // 1. Kart Bilgisi
            PaymentCard paymentCard = new PaymentCard();
            paymentCard.setCardHolderName(busCard.getFullName());
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
            item.setCategory1("BusCard");
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

            request.setCallbackUrl(baseUrl + "/v1/api/buscard/payment/3d-callback");

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
                        new TopUpSessionData(username, busCard.getCardNumber(),topUpBalanceRequest.getAmount()));

                String htmlContent = threedsInitialize.getHtmlContent();
                return new DataResponseMessage<>("3D doğrulama başlatıldı. Yönlendirme yapılıyor.", true, htmlContent);
            } else {
                return new ResponseMessage("3D başlatma başarısız: " + threedsInitialize.getErrorMessage(), false);
            }

        } catch (Exception e) {
            return new ResponseMessage("3D başlatma hatası: " + e.getMessage(), false);
        }
    }

    @Transactional
    public ResponseMessage handleSuccessfulTopUp(User user, BigDecimal amount, String paymentId, String cardNumber,HttpServletRequest httpServletRequest) throws BusCardIsBlockedException, BusCardNotActiveException, BusCardNotFoundException {

        BusCard busCard = busCardRepository.findByCardNumber(cardNumber)
                .orElseThrow(BusCardNotFoundException::new);

        if (busCard.getStatus() == CardStatus.BLOCKED) {
            throw new BusCardIsBlockedException();
        }
        if (busCard.getStatus() != CardStatus.ACTIVE) {
            throw new BusCardNotActiveException();
        }

        BigDecimal oldBalance = busCard.getBalance() == null ? BigDecimal.ZERO : busCard.getBalance();
        BigDecimal newBalance = oldBalance.add(amount);
        busCard.setBalance(newBalance);
        busCard.setLastTransactionAmount(amount);
        busCard.setLastTransactionDate(LocalDate.now());
        busCard.setTxCounter(busCard.getTxCounter() + 1);

        busCardRepository.save(busCard);

        BusCardActivity busCardActivity = new BusCardActivity();
        busCardActivity.setBusCard(busCard);
        busCardActivity.setUser(user);
        busCardActivity.setPrice(amount);
        busCardActivity.setUseDateTime(LocalDateTime.now());
        busCardActivity.setTransfer(false);
        busCardActivity.setValidatorId("TOPUP-IYZICO-" + paymentId);
        activityRepository.save(busCardActivity);

        String metadata = String.format(
                "Kart numarası: %s, Eski bakiye: %s, Yeni bakiye: %s, Payment ID: %s",
                busCard.getCardNumber(),
                oldBalance,
                newBalance,
                paymentId
        );

        userManager.updateDeviceInfoAndCreateAuditLog(
                user,
                httpServletRequest,
                geoIpService,
                ActionType.CARD_TOPUP_SUCCESS,
                String.format("Kart %s için %s TL yüklendi.", busCard.getCardNumber(), amount),
                amount.doubleValue(),
                metadata
        );

        // 7. (Opsiyonel) Bildirim gönder
        fcmService.sendNotificationToToken(
                user,
                "Kart Yükleme Başarılı",
                amount + " TL kart bakiyenize başarıyla yüklendi.",
                NotificationType.SUCCESS,
                null
        );

        log.info("BusCard {} için bakiye artırıldı: {} -> {}", cardNumber, oldBalance, newBalance);

        return new ResponseMessage("Yükleme başarılı. Yeni bakiye: " + newBalance, true);
    }


    // helper: QR PNG byte[]
    private byte[] generateQrImageBytes(String token, int width, int height)
            throws WriterException, java.io.IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(token, BarcodeFormat.QR_CODE, width, height);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
        return outputStream.toByteArray();
    }


}
