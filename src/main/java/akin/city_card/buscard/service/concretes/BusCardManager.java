package akin.city_card.buscard.service.concretes;


import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.ActionType;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.model.AuditLog;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.admin.repository.AuditLogRepository;
import akin.city_card.bus.exceptions.InsufficientBalanceException;
import akin.city_card.buscard.core.converter.BusCardConverter;
import akin.city_card.buscard.core.request.CreateCardPricingRequest;
import akin.city_card.buscard.core.request.ReadCardRequest;
import akin.city_card.buscard.core.request.RegisterCardRequest;
import akin.city_card.buscard.core.request.UpdateCardPricingRequest;
import akin.city_card.buscard.core.response.BusCardDTO;
import akin.city_card.buscard.core.response.CardPricingDTO;
import akin.city_card.buscard.exceptions.CardPricingNotFoundException;
import akin.city_card.buscard.exceptions.ExpiredQrCodeException;
import akin.city_card.buscard.exceptions.InvalidQrCodeException;
import akin.city_card.buscard.model.CardPricing;
import akin.city_card.buscard.model.CardType;
import akin.city_card.buscard.repository.BusCardRepository;
import akin.city_card.buscard.repository.CardPricingRepository;
import akin.city_card.buscard.service.abstracts.BusCardService;
import akin.city_card.geoIpService.GeoIpService;
import akin.city_card.geoIpService.GeoLocationData;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.wallet.exceptions.WalletNotActiveException;
import akin.city_card.wallet.exceptions.WalletNotFoundException;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletStatus;
import akin.city_card.wallet.repository.WalletRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class BusCardManager implements BusCardService {
    private final ObjectMapper objectMapper;
    private final BusCardRepository busCardRepository;
    private final CardPricingRepository cardPricingRepository;
    private final UserRepository userRepository;
    private final AdminRepository adminRepository;
    private final WalletRepository walletRepository;
    private final BusCardConverter busCardConverter;
    private final AuditLogRepository auditLogRepository;


    @Override
    public BusCardDTO registerCard(RegisterCardRequest req, String username) {
        return null;
    }

    @Override
    public BusCardDTO readCard(String reqUid, String uid) {
        return null;
    }

    @Override
    public BusCardDTO topUpBalance(String username, String uid, BigDecimal bigDecimal) {
        return null;
    }

    @Override
    public BusCardDTO getOn(String uid) {
        return null;
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
    public BusCardDTO cardVisa(ReadCardRequest request, String username) {
        return null;
    }

    @Override
    public BusCardDTO deleteCardBlocked(Map<String, String> request) {
        return null;
    }


    @Override
    public BusCardDTO cardBlocked(Map<String, Object> request) {
        return null;
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

    @Override
    @Transactional(rollbackFor = Exception.class)
    public byte[] generateQrCode(String username)
            throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException,
            CardPricingNotFoundException, InsufficientBalanceException {

        // 1. validate entities
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        Wallet wallet = walletRepository.findByUser(user).orElseThrow(WalletNotFoundException::new);
        CardPricing cardPricing = cardPricingRepository.findByCardType(CardType.TAM)
                .orElseThrow(CardPricingNotFoundException::new);

        if (!WalletStatus.ACTIVE.equals(wallet.getStatus())) {
            throw new WalletNotActiveException();
        }
        if (wallet.getBalance().compareTo(cardPricing.getPrice()) < 0) {
            throw new InsufficientBalanceException();
        }

        // 2. build payload
        Map<String, Object> payload = new HashMap<>();
        payload.put("v", 1);
        payload.put("userNumber", user.getUsername());
        payload.put("walletId", wallet.getWiban());
        payload.put("price", cardPricing.getPrice());
        payload.put("issuedAt", Instant.now().toEpochMilli());
        payload.put("expiresAt", Instant.now().plusSeconds(600).toEpochMilli());
        payload.put("nonce", UUID.randomUUID().toString());

        try {
            // serialize JSON
            String json = objectMapper.writeValueAsString(payload);

            // 3. generate HMAC signature
            String secret = "veryStrongSecretKeyForQRCodeHmac"; // TODO: dışarıdan config'ten al
            String signature = hmacSha256(json, secret);

            // 4. build final token: base64(payload).signature
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8))
                    + "." + signature;

            // 5. generate QR code image
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
            InsufficientBalanceException {

        try {
            // 1️⃣ Token parçala
            String[] parts = qrToken.split("\\.");
            if (parts.length != 2) {
                throw new InvalidQrCodeException();
            }

            String encodedPayload = parts[0];
            String providedSignature = parts[1];

            // 2️⃣ Payload decode et
            String json = new String(Base64.getUrlDecoder().decode(encodedPayload), StandardCharsets.UTF_8);

            // 3️⃣ İmza doğrula
            String secret = "veryStrongSecretKeyForQRCodeHmac"; // generateQrCode ile aynı olmalı
            String expectedSignature = hmacSha256(json, secret);

            if (!expectedSignature.equals(providedSignature)) {
                throw new InvalidQrCodeException();
            }

            // 4️⃣ JSON parse et
            Map<String, Object> payload = objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {
            });

            String userNumber = (String) payload.get("userNumber");
            String walletId = (String) payload.get("walletId");
            BigDecimal price = new BigDecimal(payload.get("price").toString());
            Long expiresAt = Long.valueOf(payload.get("expiresAt").toString());

            // 5️⃣ Süre dolmuş mu?
            if (Instant.now().toEpochMilli() > expiresAt) {
                throw new ExpiredQrCodeException();
            }

            // 6️⃣ Kullanıcı ve cüzdan doğrula
            User user = userRepository.findByUserNumber(userNumber)
                    .orElseThrow(UserNotFoundException::new);

            Wallet wallet = walletRepository.findByUser(user)
                    .orElseThrow(WalletNotFoundException::new);

            if (wallet.getBalance().compareTo(price) < 0) {
                throw new InsufficientBalanceException();
            }

            // 7️⃣ Bakiye düş
            wallet.setBalance(wallet.getBalance().subtract(price));
            walletRepository.save(wallet);

            // 8️⃣ Log kaydı (örnek)
            System.out.println("✅ QR başarıyla doğrulandı, bakiye düşüldü. Yeni bakiye: " + wallet.getBalance());

            // 9️⃣ ResponseMessage dön
            return new ResponseMessage(
                    "QR doğrulandı, " + price + "₺ düşüldü. Güncel bakiye: " + wallet.getBalance(), true
            );

        } catch (IOException e) {
            throw new InvalidQrCodeException();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String hmacSha256(String json, String secret) {
        return  null;
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
