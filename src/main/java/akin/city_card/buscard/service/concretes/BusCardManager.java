package akin.city_card.buscard.service.concretes;


import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.bus.exceptions.InsufficientBalanceException;
import akin.city_card.buscard.core.converter.BusCardConverter;
import akin.city_card.buscard.core.request.CreateCardPricingRequest;
import akin.city_card.buscard.core.request.RegisterCardRequest;
import akin.city_card.buscard.core.request.UpdateCardPricingRequest;
import akin.city_card.buscard.core.response.BusCardResponse;
import akin.city_card.buscard.core.response.CardPricingDTO;
import akin.city_card.buscard.exceptions.*;
import akin.city_card.buscard.model.*;
import akin.city_card.buscard.repository.BusCardRepository;
import akin.city_card.buscard.repository.CardPricingRepository;
import akin.city_card.buscard.service.abstracts.BusCardService;
import akin.city_card.response.ResponseMessage;
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
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

@Service
@Slf4j
public class BusCardManager implements BusCardService {

    private static final int IV_SIZE = 12;       // bytes
    private static final int TAG_BITS = 128;     // AES-GCM tag bits
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private final SecureRandom secureRandom = new SecureRandom();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final BusCardRepository busCardRepository;
    // Keystore config (application.properties)
    private final String keyStorePath;
    private final String keyStorePassword;
    private final String masterKeyAlias;
    @Autowired
    private CardPricingRepository cardPricingRepository;


    @Autowired
    private UserRepository userRepository;
    // masterKey cached in memory (SecretKey) — but will be loaded from keystore on startup
    private volatile SecretKey masterKey;
    @Autowired
    private AdminRepository adminRepository;
    @Autowired
    private WalletRepository walletRepository;
    @Autowired
    private BusCardConverter busCardConverter;

    public BusCardManager(
            BusCardRepository busCardRepository,
            @Value("${buscard.keystore.path}") String keyStorePath,
            @Value("${buscard.keystore.password}") String keyStorePassword,
            @Value("${buscard.masterkey.alias}") String masterKeyAlias
    ) throws Exception {
        this.busCardRepository = busCardRepository;
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.masterKeyAlias = masterKeyAlias;

        // Load or create keystore and master key on startup
        this.masterKey = loadOrCreateMasterKey();
    }

    @Override
    public ResponseEntity<?> registerCard(RegisterCardRequest req) {
        try {
            // 1️⃣ Aynı kart kayıtlı mı kontrol et
            BusCard existingCard = busCardRepository.findByCardNumber(req.getUid());
            if (existingCard != null) {
                throw new BusCardAlreadyExistsException(req.getUid());
            }

            // 2️⃣ Yeni kart oluştur
            BusCard busCard = new BusCard();
            busCard.setCardNumber(req.getUid());
            busCard.setFullName(req.getFullName()); // isim eklendi
            busCard.setType(req.getKartTipi());
            busCard.setStatus(req.getStatus() != null ? req.getStatus() : CardStatus.ACTIVE);
            busCard.setActive(req.isAktif());
            busCard.setBalance(req.getBakiye() != null ? req.getBakiye() : BigDecimal.ZERO);
            busCard.setLastTransactionAmount(req.getSonIslemTutari() != null ? req.getSonIslemTutari() : BigDecimal.ZERO);
            busCard.setVisaCompleted(req.isVizeTamamlandi());
            busCard.setLowBalanceNotified(false);
            busCard.setIssueDate(LocalDate.now());
            busCard.setExpiryDate(req.getKartVizeBitisTarihi() != null && req.getKartVizeBitisTarihi() > 0
                    ? Instant.ofEpochSecond(req.getKartVizeBitisTarihi()).atZone(ZoneId.systemDefault()).toLocalDate()
                    : null);

            if (req.getSonIslemTarihi() != null && req.getSonIslemTarihi() > 0) {
                busCard.setLastTransactionDate(
                        Instant.ofEpochSecond(req.getSonIslemTarihi()).atZone(ZoneId.systemDefault()).toLocalDate()
                );
            }

            // 3️⃣ Abonman bilgisi
            if (req.isAbonmanMi()) {
                SubscriptionInfo subscriptionInfo = new SubscriptionInfo();
                subscriptionInfo.setType(busCard.getType().name());
                subscriptionInfo.setLoaded(req.getAbonmanBinisSayisi() != null ? req.getAbonmanBinisSayisi() : 0);
                subscriptionInfo.setStartDate(LocalDate.now());
                subscriptionInfo.setEndDate(req.getAbonmanBitisTarihi() != null && req.getAbonmanBitisTarihi() > 0
                        ? Instant.ofEpochSecond(req.getAbonmanBitisTarihi()).atZone(ZoneId.systemDefault()).toLocalDate()
                        : null);
                busCard.setSubscriptionInfo(subscriptionInfo);
            }

            if (busCard.getTxCounter() == null) busCard.setTxCounter(0);

            // 4️⃣ DataKey oluştur ve masterKey ile şifrele
            byte[] dataKey = generateDataKey();
            byte[] encryptedDataKey = wrapDataKeyWithMaster(masterKey, dataKey);
            busCard.setEncryptedDataKey(encryptedDataKey);

            // 5️⃣ Payload oluştur — kartın içine yazılacak veri
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("uid", busCard.getCardNumber());
            payload.put("fullName", busCard.getFullName());
            payload.put("cardType", busCard.getType().name());
            payload.put("cardStatus", busCard.getStatus().name());
            payload.put("active", busCard.isActive());
            payload.put("balance", busCard.getBalance());
            payload.put("lowBalanceNotified", busCard.isLowBalanceNotified());
            payload.put("lastTransactionAmount", busCard.getLastTransactionAmount());
            payload.put("lastTransactionDate", busCard.getLastTransactionDate() != null ? busCard.getLastTransactionDate().toString() : null);
            payload.put("visaCompleted", busCard.isVisaCompleted());
            payload.put("issueDate", busCard.getIssueDate().toString());
            payload.put("expiryDate", busCard.getExpiryDate() != null ? busCard.getExpiryDate().toString() : null);
            payload.put("abonmanMi", req.isAbonmanMi());
            payload.put("subscriptionLoaded", req.getAbonmanBinisSayisi() != null ? req.getAbonmanBinisSayisi() : 0);
            payload.put("subscriptionEndDate", req.getAbonmanBitisTarihi() != null && req.getAbonmanBitisTarihi() > 0
                    ? Instant.ofEpochSecond(req.getAbonmanBitisTarihi()).atZone(ZoneId.systemDefault()).toLocalDate().toString()
                    : null);
            payload.put("cardVisaExpiry", req.getKartVizeBitisTarihi());
            payload.put("txCounter", busCard.getTxCounter());
            payload.put("issuedAt", Instant.now().getEpochSecond());
            payload.put("packageId", "pkg_" + Instant.now().toEpochMilli());
            payload.put("encryptionVersion", "v1.1");
            payload.put("systemId", "AKIN_CITY_CARD");
            payload.put("issuer", "CityCardCentralServer");
            payload.put("securityLevel", "AES-GCM-256");

            // 6️⃣ Payload’ı AES-GCM ile şifrele
            byte[] plain = objectMapper.writeValueAsBytes(payload);
            String packageBase64 = encryptWithAesGcm(dataKey, plain);

            zeroize(plain);
            zeroize(dataKey);

            busCard.setPackageBase64(packageBase64);
            busCardRepository.save(busCard);

            // 7️⃣ Response hazırla
            Map<String, Object> resp = new HashMap<>();
            resp.put("packageBase64", packageBase64);
            resp.put("startSector", 4);
            resp.put("startBlockOffset", 0);
            resp.put("maxBlocks", 12);
            resp.put("packageId", payload.get("packageId"));
            resp.put("encryptionVersion", "v1.1");

            return ResponseEntity.ok(resp);

        } catch (BusCardAlreadyExistsException e) {
            return ResponseEntity.status(409).body(Map.of("error", e.getMessage())); // 409 Conflict
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "Kart kayıt hatası: " + e.getMessage()));
        }
    }

    @Override
    @Transactional(readOnly = true)
    public ResponseEntity<?> readCard(String uid) {
        if (uid == null || uid.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "UID zorunlu"));
        }

        try {
            BusCard busCard = busCardRepository.findByCardNumber(uid);
            if (busCard == null) {
                return ResponseEntity.status(404).body(Map.of("error", "Kart bulunamadı"));
            }

            byte[] plain = decryptPackageForCard(busCard, busCard.getPackageBase64());

            Map<String, Object> payload = objectMapper.readValue(plain, Map.class);

            // Belleği temizle
            java.util.Arrays.fill(plain, (byte) 0);

            // DTO oluştur ve doldur
            BusCardResponse response = new BusCardResponse();
            response.setUid((String) payload.get("uid"));
            response.setFullName((String) payload.get("fullName"));
            response.setCardType((String) payload.get("cardType"));
            response.setCardStatus((String) payload.get("cardStatus"));
            response.setActive(Boolean.parseBoolean(payload.get("active").toString()));
            response.setBalance(new BigDecimal(payload.get("balance").toString()));
            response.setLowBalanceNotified(Boolean.parseBoolean(payload.get("lowBalanceNotified").toString()));
            response.setLastTransactionAmount(new BigDecimal(payload.get("lastTransactionAmount").toString()));

            if (payload.get("lastTransactionDate") != null && !payload.get("lastTransactionDate").toString().isEmpty()) {
                response.setLastTransactionDate(LocalDate.parse(payload.get("lastTransactionDate").toString()));
            }

            response.setVisaCompleted(Boolean.parseBoolean(payload.get("visaCompleted").toString()));
            response.setIssueDate(LocalDate.parse(payload.get("issueDate").toString()));

            if (payload.get("expiryDate") != null && !payload.get("expiryDate").toString().isEmpty()) {
                response.setExpiryDate(LocalDate.parse(payload.get("expiryDate").toString()));
            }

            response.setAbonmanMi(Boolean.parseBoolean(payload.get("abonmanMi").toString()));
            response.setSubscriptionLoaded(Integer.parseInt(payload.get("subscriptionLoaded").toString()));

            if (payload.get("subscriptionEndDate") != null && !payload.get("subscriptionEndDate").toString().isEmpty()) {
                response.setSubscriptionEndDate(LocalDate.parse(payload.get("subscriptionEndDate").toString()));
            }

            response.setCardVisaExpiry(payload.get("cardVisaExpiry") != null ? Long.valueOf(payload.get("cardVisaExpiry").toString()) : null);
            response.setTxCounter(Integer.parseInt(payload.get("txCounter").toString()));
            response.setIssuedAt(Long.valueOf(payload.get("issuedAt").toString()));
            response.setPackageId((String) payload.get("packageId"));
            response.setEncryptionVersion((String) payload.get("encryptionVersion"));
            response.setSystemId((String) payload.get("systemId"));
            response.setIssuer((String) payload.get("issuer"));
            response.setSecurityLevel((String) payload.get("securityLevel"));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "Kart okuma hatası: " + e.getMessage()));
        }
    }

    @Override
    @Transactional
    public ResponseEntity<?> topUpBalance(String uid, BigDecimal amount) {
        try {
            // 0️⃣ Giriş validasyonu
            if (uid == null || uid.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "UID zorunlu"));
            }
            if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
                throw new InvalidTopUpAmountException();
            }

            // 1️⃣ Kartı bul
            BusCard busCard = busCardRepository.findByCardNumber(uid);
            if (busCard == null) {
                throw new BusCardNotFoundException();
            }

            // 2️⃣ Kart aktif mi?
            if (!busCard.isActive()) {
                throw new InactiveCardException(uid);
            }

            // 3️⃣ Kartın vizesi bitmiş mi?
            if (busCard.getExpiryDate() != null && busCard.getExpiryDate().isBefore(LocalDate.now())) {
                throw new CardExpiredException(uid);
            }

            // 4️⃣ Bakiye güncelle
            BigDecimal newBalance = (busCard.getBalance() != null ? busCard.getBalance() : BigDecimal.ZERO)
                    .add(amount);
            busCard.setBalance(newBalance);
            busCard.setLastTransactionAmount(amount);
            busCard.setLastTransactionDate(LocalDate.now());

            // 5️⃣ TX Counter artır
            int tx = busCard.getTxCounter() == null ? 1 : busCard.getTxCounter() + 1;
            busCard.setTxCounter(tx);

            // 6️⃣ Payload hazırlığı (kart üzerine yazılacak minimum veri)
            long nowEpoch = Instant.now().getEpochSecond();
            String packageId = "pkg_" + Instant.now().toEpochMilli();

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("uid", busCard.getCardNumber());
            payload.put("fullName", busCard.getFullName());
            payload.put("cardType", busCard.getType() != null ? busCard.getType().name() : "");
            payload.put("cardStatus", busCard.getStatus() != null ? busCard.getStatus().name() : "");
            payload.put("active", busCard.isActive());
            payload.put("balance", newBalance);
            payload.put("lastTransactionAmount", amount);
            payload.put("lastTransactionDate", nowEpoch);
            payload.put("abonmanMi", busCard.getSubscriptionInfo() != null);
            payload.put("subscriptionLoaded", busCard.getSubscriptionInfo() != null ? busCard.getSubscriptionInfo().getLoaded() : 0);
            payload.put("issuedAt", nowEpoch);
            payload.put("packageId", packageId);
            payload.put("systemId", "AKIN_CITY_CARD");
            payload.put("encryptionVersion", "v1.1");

            // 7️⃣ Payload AES-GCM ile şifrele
            String packageBase64;
            byte[] dataKey = null;
            try {
                dataKey = retrieveDataKey(busCard);
                byte[] plain = objectMapper.writeValueAsBytes(payload);
                packageBase64 = encryptWithAesGcm(dataKey, plain);
                zeroize(plain);
                busCard.setPackageBase64(packageBase64);
            } finally {
                if (dataKey != null) zeroize(dataKey);
            }

            // 8️⃣ DB kaydet
            busCardRepository.save(busCard);

            // 9️⃣ Kart üzerine yazma talimatı
            Map<String, Object> cardWrite = new LinkedHashMap<>();
            cardWrite.put("startSector", 4);
            cardWrite.put("startBlockOffset", 0);
            cardWrite.put("maxBlocks", 12);
            cardWrite.put("encryptionVersion", payload.get("encryptionVersion"));
            cardWrite.put("packageId", packageId);
            cardWrite.put("packageBase64", packageBase64);

            // 10️⃣ Server-side DTO
            BusCardResponse responseDto = BusCardResponse.builder()
                    .uid(busCard.getCardNumber())
                    .fullName(busCard.getFullName())
                    .cardType(busCard.getType() != null ? busCard.getType().name() : null)
                    .cardStatus(busCard.getStatus() != null ? busCard.getStatus().name() : null)
                    .active(busCard.isActive())
                    .balance(busCard.getBalance())
                    .lowBalanceNotified(busCard.isLowBalanceNotified())
                    .lastTransactionAmount(busCard.getLastTransactionAmount())
                    .lastTransactionDate(busCard.getLastTransactionDate())
                    .abonmanMi(busCard.getSubscriptionInfo() != null)
                    .subscriptionLoaded(busCard.getSubscriptionInfo() != null ? busCard.getSubscriptionInfo().getLoaded() : 0)
                    .subscriptionEndDate(busCard.getSubscriptionInfo() != null ? busCard.getSubscriptionInfo().getEndDate() : null)
                    .txCounter(busCard.getTxCounter())
                    .issuedAt(nowEpoch)
                    .packageId(packageId)
                    .encryptionVersion("v1.1")
                    .systemId("AKIN_CITY_CARD")
                    .issuer("CityCardCentralServer")
                    .securityLevel("AES-GCM-256")
                    .build();

            // 11️⃣ Final response
            Map<String, Object> finalResp = new LinkedHashMap<>();
            finalResp.putAll(cardWrite);
            finalResp.put("serverState", responseDto);

            return ResponseEntity.ok(finalResp);

        } catch (InvalidTopUpAmountException | InactiveCardException | CardExpiredException |
                 BusCardNotFoundException e) {
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        } catch (DataKeyNotFoundException | InvalidDataKeyException e) {
            return ResponseEntity.status(500).body(Map.of("error", "Şifreleme anahtarı hatası: " + e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "Bakiye yükleme hatası: " + e.getMessage()));
        }
    }

    @Override
    @Transactional
    public ResponseEntity<?> getOn(String uid) {
        try {
            // 0️⃣ Giriş validasyonu
            if (uid == null || uid.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "UID zorunlu"));
            }

            // 1️⃣ Kartı bul
            BusCard busCard = busCardRepository.findByCardNumber(uid);
            if (busCard == null) {
                throw new BusCardNotFoundException();
            }

            // 2️⃣ Kart aktif mi?
            if (!busCard.isActive()) {
                throw new InactiveCardException(uid);
            }

            // 3️⃣ Kartın vizesi bitmiş mi?
            if (busCard.getExpiryDate() != null && busCard.getExpiryDate().isBefore(LocalDate.now())) {
                throw new CardExpiredException(uid);
            }

            // 4️⃣ Ücret tablosu (10 - 20 arası)
            Map<CardType, BigDecimal> fareTable = Map.of(
                    CardType.TAM, BigDecimal.valueOf(20),
                    CardType.ÖĞRENCİ, BigDecimal.valueOf(12),
                    CardType.ÖĞRETMEN, BigDecimal.valueOf(15),
                    CardType.YAŞLI, BigDecimal.valueOf(10),
                    CardType.ENGELLİ, BigDecimal.valueOf(10),
                    CardType.ÇOCUK, BigDecimal.valueOf(10),
                    CardType.TURİST, BigDecimal.valueOf(18),
                    CardType.ABONMAN, BigDecimal.valueOf(0)
            );
            BigDecimal fare = fareTable.getOrDefault(busCard.getType(), BigDecimal.valueOf(20));

            // 5️⃣ Abonman kontrolü
            boolean usedSubscription = false;
            if (busCard.getSubscriptionInfo() != null) {
                SubscriptionInfo sub = busCard.getSubscriptionInfo();
                if (sub.getEndDate() == null || !sub.getEndDate().isBefore(LocalDate.now())) {
                    if (sub.getLoaded() != 0 && sub.getLoaded() > 0) {
                        sub.setLoaded(sub.getLoaded() - 1);
                        usedSubscription = true;
                    }
                }
            }

            // 6️⃣ Eğer abonman kullanılmadıysa, bakiye düş
            if (!usedSubscription) {
                BigDecimal currentBalance = busCard.getBalance() != null ? busCard.getBalance() : BigDecimal.ZERO;
                if (currentBalance.compareTo(fare) < 0) {
                    return ResponseEntity.status(402).body(Map.of("error", "Yetersiz bakiye"));
                }
                busCard.setBalance(currentBalance.subtract(fare));
                busCard.setLastTransactionAmount(fare);
                busCard.setLastTransactionDate(LocalDate.now());
            } else {
                busCard.setLastTransactionAmount(BigDecimal.ZERO);
                busCard.setLastTransactionDate(LocalDate.now());
            }

            // 7️⃣ TX Counter artır (null-safe)
            int tx = busCard.getTxCounter() == null ? 1 : busCard.getTxCounter() + 1;
            busCard.setTxCounter(tx);

            // 8️⃣ Payload hazırlığı (kart üzerine yazılacak minimum veri)
            long nowEpoch = Instant.now().getEpochSecond();
            String packageId = "pkg_" + Instant.now().toEpochMilli();

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("uid", busCard.getCardNumber());
            payload.put("txCounter", busCard.getTxCounter());
            payload.put("lastTransactionAmount", busCard.getLastTransactionAmount());
            payload.put("lastTransactionDate", nowEpoch);
            payload.put("abonmanMi", busCard.getSubscriptionInfo() != null);
            payload.put("subscriptionLoaded", busCard.getSubscriptionInfo() != null ? busCard.getSubscriptionInfo().getLoaded() : 0);
            payload.put("issuedAt", nowEpoch);
            payload.put("packageId", packageId);
            payload.put("systemId", "AKIN_CITY_CARD");
            payload.put("encryptionVersion", "v1.1");

            // 9️⃣ Payload'ı AES-GCM ile şifrele (dataKey unwrap + encrypt)
            String packageBase64;
            byte[] dataKey = null;
            try {
                dataKey = retrieveDataKey(busCard); // throws DataKeyNotFoundException / InvalidDataKeyException
                byte[] plain = objectMapper.writeValueAsBytes(payload);
                packageBase64 = encryptWithAesGcm(dataKey, plain);
                zeroize(plain);
                // veritabanına da kaydettiğimiz güncel paket
                busCard.setPackageBase64(packageBase64);
            } finally {
                if (dataKey != null) zeroize(dataKey);
            }

            // 10️⃣ DB kaydet
            busCardRepository.save(busCard);

            // 11️⃣ Kart üzerine yazma talimatı (POS/Reader için)
            Map<String, Object> cardWrite = new LinkedHashMap<>();
            cardWrite.put("startSector", 4);
            cardWrite.put("startBlockOffset", 0);
            cardWrite.put("maxBlocks", 12);
            cardWrite.put("encryptionVersion", payload.get("encryptionVersion"));
            cardWrite.put("packageId", packageId);
            cardWrite.put("packageBase64", packageBase64);

            // 12️⃣ Sunucu tarafı dönecek DTO (isteğe bağlı, hem cardWrite hem server state dönebilir)
            BusCardResponse responseDto = BusCardResponse.builder()
                    .uid(busCard.getCardNumber())
                    .fullName(busCard.getFullName())
                    .cardType(busCard.getType() != null ? busCard.getType().name() : null)
                    .cardStatus(busCard.getStatus() != null ? busCard.getStatus().name() : null)
                    .active(busCard.isActive())
                    .balance(busCard.getBalance())
                    .lowBalanceNotified(busCard.isLowBalanceNotified())
                    .lastTransactionAmount(busCard.getLastTransactionAmount())
                    .lastTransactionDate(busCard.getLastTransactionDate())
                    .abonmanMi(busCard.getSubscriptionInfo() != null)
                    .subscriptionLoaded(busCard.getSubscriptionInfo() != null ? busCard.getSubscriptionInfo().getLoaded() : 0)
                    .subscriptionEndDate(busCard.getSubscriptionInfo() != null ? busCard.getSubscriptionInfo().getEndDate() : null)
                    .txCounter(busCard.getTxCounter())
                    .issuedAt(nowEpoch)
                    .packageId(packageId)
                    .encryptionVersion("v1.1")
                    .systemId("AKIN_CITY_CARD")
                    .issuer("CityCardCentralServer")
                    .securityLevel("AES-GCM-256")
                    .build();

            // 13️⃣ Final response: hem yazılacak paket hem de server-side DTO
            Map<String, Object> finalResp = new LinkedHashMap<>();
            finalResp.putAll(cardWrite);
            finalResp.put("serverState", responseDto);

            return ResponseEntity.ok(finalResp);

        } catch (BusCardNotFoundException | InactiveCardException | CardExpiredException e) {
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        } catch (DataKeyNotFoundException | InvalidDataKeyException e) {
            return ResponseEntity.status(500).body(Map.of("error", "Şifreleme anahtarı hatası: " + e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "GetOn hatası: " + e.getMessage()));
        }
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
    public ResponseEntity<?> cardVisa(Map<String, Object> request) {
        return null;
    }

    @Override
    public ResponseEntity<?> deleteCardBlocked(Map<String, String> request) {
        return null;
    }

    @Override
    public ResponseEntity<?> cardBlocked(Map<String, Object> request) {
        return null;
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


    // HMAC oluşturucu
    private String hmacSha256(String data, String secret) throws Exception {
        Mac sha256Hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256Hmac.init(keySpec);
        byte[] macData = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(macData);
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


    /**
     * DB'deki encryptedDataKey'i master key ile çözerek kullanıma hazır dataKey döndürür.
     */
    private byte[] retrieveDataKey(BusCard busCard) throws Exception {
        byte[] encryptedDataKey = busCard.getEncryptedDataKey();
        if (encryptedDataKey == null || encryptedDataKey.length == 0) {
            throw new IllegalStateException("Kart için şifrelenmiş data key bulunamadı");
        }

        // masterKey ile çöz (unwrap)
        byte[] dataKey = unwrapDataKeyWithMaster(masterKey, encryptedDataKey);

        if (dataKey == null || dataKey.length != 16) { // AES-128 için 16 byte
            throw new IllegalStateException("Data key geçersiz veya bozulmuş");
        }

        return dataKey; // kullanımdan sonra zeroize edilmeli
    }

    /**
     * Master key ile wrap edilmiş dataKey'i çözmek için basit AES-GCM unwrap örneği.
     *
     * @param masterKey      uygulamanın master key'i (AES-128/256)
     * @param wrappedDataKey DB'den alınan şifrelenmiş key
     * @return plain data key
     */
    private byte[] unwrapDataKeyWithMaster(byte[] masterKey, byte[] wrappedDataKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12]; // örnek: ilk 12 byte iv olabilir, gerçek implementasyonda saklanmalı
        System.arraycopy(wrappedDataKey, 0, iv, 0, 12);
        byte[] cipherText = new byte[wrappedDataKey.length - 12];
        System.arraycopy(wrappedDataKey, 12, cipherText, 0, cipherText.length);

        SecretKeySpec keySpec = new SecretKeySpec(masterKey, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(cipherText);
    }


    /**
     * Decrypt packaged Base64 using encryptedDataKey from DB and masterKey
     */
    public byte[] decryptPackageForCard(BusCard busCard, String packageBase64) throws Exception {
        byte[] encryptedDataKey = busCard.getEncryptedDataKey();
        if (encryptedDataKey == null || encryptedDataKey.length == 0) {
            throw new IllegalStateException("Kart için şifrelenmiş anahtar bulunamadı");
        }

        // unwrap data key with master key (keystore)
        byte[] dataKey = unwrapDataKeyWithMaster(masterKey, encryptedDataKey);

        try {
            byte[] packaged = Base64.getDecoder().decode(packageBase64);
            ByteBuffer buffer = ByteBuffer.wrap(packaged);
            buffer.get(); // version
            int payloadLen = buffer.getShort() & 0xFFFF;
            byte[] iv = new byte[IV_SIZE];
            buffer.get(iv);
            byte[] cipherText = new byte[buffer.remaining()];
            buffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            SecretKeySpec keySpec = new SecretKeySpec(dataKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            return cipher.doFinal(cipherText);
        } finally {
            // dataKey'i sıfırla
            zeroize(dataKey);
        }
    }

    /**
     * Utility: byte array temizleme
     */
    private void zeroize(byte[] array) {
        if (array != null) {
            java.util.Arrays.fill(array, (byte) 0);
        }
    }


    // ---------------- helper methods ----------------

    // Generate random AES-128 data key
    private byte[] generateDataKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();
        byte[] dataKey = key.getEncoded();
        // try to zeroize SecretKey if possible (gc may keep copy)
        return dataKey;
    }

    // Wrap dataKey with masterKey using AES-GCM (we store iv + ciphertext)
    private byte[] wrapDataKeyWithMaster(SecretKey master, byte[] dataKey) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        SecretKeySpec mkSpec = new SecretKeySpec(master.getEncoded(), "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, mkSpec, gcmSpec);
        byte[] cipherText = cipher.doFinal(dataKey);

        // packaged: iv(12) + cipherText (includes tag)
        ByteBuffer bb = ByteBuffer.allocate(IV_SIZE + cipherText.length);
        bb.put(iv);
        bb.put(cipherText);
        return bb.array();
    }

    // Unwrap dataKey: decrypt encryptedDataKey with masterKey
    private byte[] unwrapDataKeyWithMaster(SecretKey master, byte[] encryptedDataKey) throws Exception {
        ByteBuffer bb = ByteBuffer.wrap(encryptedDataKey);
        byte[] iv = new byte[IV_SIZE];
        bb.get(iv);
        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        SecretKeySpec mkSpec = new SecretKeySpec(master.getEncoded(), "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, mkSpec, gcmSpec);
        byte[] dataKeyPlain = cipher.doFinal(cipherText);
        return dataKeyPlain;
    }

    // Encrypt payload with dataKey using AES-GCM; returns packaged Base64: version|len|iv|cipher+tag
    private String encryptWithAesGcm(byte[] dataKey, byte[] plain) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(dataKey, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] cipherText = cipher.doFinal(plain);

        ByteBuffer buffer = ByteBuffer.allocate(1 + 2 + IV_SIZE + cipherText.length);
        buffer.put((byte) 1);
        buffer.putShort((short) plain.length);
        buffer.put(iv);
        buffer.put(cipherText);
        return Base64.getEncoder().encodeToString(buffer.array());
    }


    // Load existing master key from JCEKS keystore, or create and store one if not exists (local dev)
    private SecretKey loadOrCreateMasterKey() throws Exception {
        File ksFile = new File(keyStorePath);
        KeyStore ks = KeyStore.getInstance("JCEKS");
        char[] pwd = keyStorePassword.toCharArray();

        if (ksFile.exists()) {
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                ks.load(fis, pwd);
            }
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) ks.getEntry(masterKeyAlias, new KeyStore.PasswordProtection(pwd));
            if (entry != null) {
                return entry.getSecretKey();
            } else {
                // no key entry found; create one
                SecretKey sk = generateMasterKey();
                KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(sk);
                ks.setEntry(masterKeyAlias, skEntry, new KeyStore.PasswordProtection(pwd));
                try (FileOutputStream fos = new FileOutputStream(ksFile)) {
                    ks.store(fos, pwd);
                }
                return sk;
            }
        } else {
            // create keystore and master key
            ks.load(null, pwd);
            SecretKey sk = generateMasterKey();
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(sk);
            ks.setEntry(masterKeyAlias, skEntry, new KeyStore.PasswordProtection(pwd));
            try (FileOutputStream fos = new FileOutputStream(ksFile)) {
                ks.store(fos, pwd);
            }
            return sk;
        }
    }

    // generate master AES-256 key for keystore
    private SecretKey generateMasterKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256); // master key AES-256
        return kg.generateKey();
    }


}
