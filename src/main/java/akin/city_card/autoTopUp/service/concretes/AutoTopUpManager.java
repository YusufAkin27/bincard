package akin.city_card.autoTopUp.service.concretes;

import akin.city_card.autoTopUp.core.request.AutoTopUpConfigRequest;
import akin.city_card.autoTopUp.core.response.AutoTopUpConfigDTO;
import akin.city_card.autoTopUp.core.response.AutoTopUpLogDTO;
import akin.city_card.autoTopUp.core.response.AutoTopUpStatsDTO;
import akin.city_card.autoTopUp.model.AutoTopUpConfig;
import akin.city_card.autoTopUp.model.AutoTopUpLog;
import akin.city_card.autoTopUp.repository.AutoTopUpConfigRepository;
import akin.city_card.autoTopUp.repository.AutoTopUpLogRepository;
import akin.city_card.autoTopUp.service.abstracts.AutoTopUpService;
import akin.city_card.buscard.exceptions.BusCardNotFoundException;
import akin.city_card.buscard.model.BusCard;
import akin.city_card.buscard.repository.BusCardRepository;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.AutoTopUpConfigNotFoundException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.wallet.exceptions.WalletIsEmptyException;
import akin.city_card.wallet.model.TransactionType;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletTransaction;
import akin.city_card.wallet.repository.WalletRepository;
import akin.city_card.wallet.repository.WalletTransactionRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AutoTopUpManager implements AutoTopUpService {

    private final AutoTopUpConfigRepository autoTopUpConfigRepository;
    private final AutoTopUpLogRepository autoTopUpLogRepository;
    private final UserRepository userRepository;
    private final BusCardRepository busCardRepository;
    private final WalletRepository walletRepository;
    private final WalletTransactionRepository walletTransactionRepository;

    @Override
    public List<AutoTopUpConfigDTO> getAutoTopUpConfigs(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        List<AutoTopUpConfig> configs = autoTopUpConfigRepository.findByUserAndActiveOrderByCreatedAtDesc(user, true);

        return configs.stream().map(this::mapToAutoTopUpConfigDTO).collect(Collectors.toList());
    }

    @Override
    @Transactional
    public ResponseMessage addAutoTopUpConfig(String username, AutoTopUpConfigRequest configRequest)
            throws UserNotFoundException, BusCardNotFoundException, WalletIsEmptyException {

        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        BusCard busCard = busCardRepository.findById(configRequest.getBusCard())
                .orElseThrow(BusCardNotFoundException::new);

        // Cüzdan kontrolü
        Wallet wallet = user.getWallet();
        if (wallet == null) {
            throw new WalletIsEmptyException();
        }

        // Bu kart için zaten aktif bir otomatik yükleme var mı kontrol et
        boolean hasActiveConfig = autoTopUpConfigRepository.existsByBusCardAndActive(busCard, true);
        if (hasActiveConfig) {
            return new ResponseMessage("Bu kart için zaten aktif bir otomatik yükleme konfigürasyonu bulunmaktadır.", false);
        }

        // Minimum cüzdan bakiyesi kontrolü
        if (wallet.getBalance().compareTo(configRequest.getAmount()) < 0) {
            return new ResponseMessage("Cüzdan bakiyeniz otomatik yükleme tutarından az. Minimum " +
                    configRequest.getAmount() + " TL bakiye gereklidir.", false);
        }


        AutoTopUpConfig autoTopUpConfig = AutoTopUpConfig.builder()
                .user(user)
                .busCard(busCard)
                .wallet(wallet)
                .threshold(configRequest.getThreshold())
                .amount(configRequest.getAmount())
                .active(true)
                .lastTopUpAt(null)
                .createdAt(LocalDateTime.now())
                .autoTopUpLogs(new ArrayList<>())
                .build();

        autoTopUpConfigRepository.save(autoTopUpConfig);

        log.info("Otomatik yükleme konfigürasyonu oluşturuldu: Kullanıcı={}, Kart={}, Eşik={}, Tutar={}",
                username, busCard.getCardNumber(), configRequest.getThreshold(), configRequest.getAmount());

        return new ResponseMessage("Otomatik yükleme konfigürasyonu başarıyla oluşturuldu.", true);
    }

    @Override
    @Transactional
    public ResponseMessage updateAutoTopUpConfig(String username, Long configId, AutoTopUpConfigRequest configRequest)
            throws UserNotFoundException, AutoTopUpConfigNotFoundException, BusCardNotFoundException {

        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        BusCard busCard = busCardRepository.findById(configRequest.getBusCard()).orElseThrow(BusCardNotFoundException::new);
        AutoTopUpConfig config = autoTopUpConfigRepository.findByIdAndUser(configId, user)
                .orElseThrow(AutoTopUpConfigNotFoundException::new);

        // Cüzdan bakiyesi kontrolü
        Wallet wallet = user.getWallet();
        if (wallet != null && wallet.getBalance().compareTo(configRequest.getAmount()) < 0) {
            return new ResponseMessage("Cüzdan bakiyeniz yeni otomatik yükleme tutarından az.", false);
        }


        config.setThreshold(configRequest.getThreshold());
        config.setAmount(configRequest.getAmount());
        config.setBusCard(busCard);

        autoTopUpConfigRepository.save(config);

        log.info("Otomatik yükleme konfigürasyonu güncellendi: ConfigId={}, Kullanıcı={}, Yeni Eşik={}, Yeni Tutar={}",
                configId, username, configRequest.getThreshold(), configRequest.getAmount());

        return new ResponseMessage("Otomatik yükleme konfigürasyonu başarıyla güncellendi.", true);
    }

    @Override
    @Transactional
    public ResponseMessage deleteAutoTopUpConfig(String username, Long configId)
            throws AutoTopUpConfigNotFoundException, UserNotFoundException {

        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        AutoTopUpConfig config = autoTopUpConfigRepository.findByIdAndUser(configId, user)
                .orElseThrow(AutoTopUpConfigNotFoundException::new);

        config.setActive(false);
        autoTopUpConfigRepository.save(config);

        log.info("Otomatik yükleme konfigürasyonu deaktive edildi: ConfigId={}, Kullanıcı={}", configId, username);

        return new ResponseMessage("Otomatik yükleme konfigürasyonu başarıyla kapatıldı.", true);
    }

    @Override
    @Transactional
    public ResponseMessage toggleAutoTopUpConfig(String username, Long configId)
            throws UserNotFoundException, AutoTopUpConfigNotFoundException {

        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        AutoTopUpConfig config = autoTopUpConfigRepository.findByIdAndUser(configId, user)
                .orElseThrow(AutoTopUpConfigNotFoundException::new);

        config.setActive(!config.isActive());
        autoTopUpConfigRepository.save(config);

        String status = config.isActive() ? "aktive" : "deaktive";
        log.info("Otomatik yükleme konfigürasyonu {} edildi: ConfigId={}, Kullanıcı={}", status, configId, username);

        return new ResponseMessage("Otomatik yükleme konfigürasyonu " + status + " edildi.", true);
    }

    @Override
    @Transactional
    public ResponseMessage processAutoTopUp(Long busCardId, BigDecimal currentBalance) {
        try {
            BusCard busCard = busCardRepository.findById(busCardId)
                    .orElseThrow(BusCardNotFoundException::new);

            // Bu kart için aktif otomatik yükleme konfigürasyonu var mı?
            Optional<AutoTopUpConfig> configOpt = autoTopUpConfigRepository.findByBusCardAndActive(busCard, true);

            if (configOpt.isEmpty()) {
                return new ResponseMessage("Bu kart için aktif otomatik yükleme konfigürasyonu bulunamadı.", false);
            }

            AutoTopUpConfig config = configOpt.get();

            // Eşik kontrolü
            if (currentBalance.compareTo(config.getThreshold()) > 0) {
                log.debug("Kart bakiyesi ({}) eşik değerinden ({}) yüksek, otomatik yükleme yapılmayacak",
                        currentBalance, config.getThreshold());
                return new ResponseMessage("Kart bakiyesi eşik değerinden yüksek, otomatik yükleme gerekli değil.", true);
            }


            return executeAutoTopUp(config, currentBalance);

        } catch (Exception e) {
            log.error("Otomatik yükleme işlemi sırasında hata: ", e);
            return new ResponseMessage("Otomatik yükleme işlemi başarısız: " + e.getMessage(), false);
        }
    }

    @Override
    @Transactional
    public ResponseMessage processAutoTopUpForUser(String username) {
        try {
            User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

            List<AutoTopUpConfig> activeConfigs = autoTopUpConfigRepository.findByUserAndActive(user, true);

            if (activeConfigs.isEmpty()) {
                return new ResponseMessage("Aktif otomatik yükleme konfigürasyonu bulunamadı.", false);
            }

            int successCount = 0;
            int totalCount = activeConfigs.size();

            for (AutoTopUpConfig config : activeConfigs) {
                BusCard busCard = config.getBusCard();
                BigDecimal currentBalance = busCard.getBalance();

                if (currentBalance.compareTo(config.getThreshold()) <= 0) {
                    ResponseMessage result = executeAutoTopUp(config, currentBalance);
                    if (result.isSuccess()) {
                        successCount++;
                    }
                }

            }

            return new ResponseMessage(
                    String.format("Otomatik yükleme işlemi tamamlandı. %d/%d konfigürasyon başarılı.", successCount, totalCount),
                    successCount > 0
            );

        } catch (Exception e) {
            log.error("Kullanıcı otomatik yükleme işlemi sırasında hata: ", e);
            return new ResponseMessage("Otomatik yükleme işlemi başarısız: " + e.getMessage(), false);
        }
    }

    @Override
    @Transactional
    public void processAllPendingAutoTopUps() {
        try {
            List<AutoTopUpConfig> allActiveConfigs = autoTopUpConfigRepository.findByActive(true);

            log.info("Toplam {} aktif otomatik yükleme konfigürasyonu kontrol ediliyor", allActiveConfigs.size());

            int processedCount = 0;

            for (AutoTopUpConfig config : allActiveConfigs) {
                try {
                    BusCard busCard = config.getBusCard();
                    BigDecimal currentBalance = busCard.getBalance();

                    if (currentBalance != null && config.getThreshold() != null &&
                            currentBalance.compareTo(config.getThreshold()) <= 0) {

                        ResponseMessage result = executeAutoTopUp(config, currentBalance);
                        if (result.isSuccess()) {
                            processedCount++;
                        }
                    }

                } catch (Exception e) {
                    log.error("Config ID {} için otomatik yükleme hatası: ", config.getId(), e);
                }
            }

            log.info("Otomatik yükleme batch işlemi tamamlandı. {} işlem gerçekleştirildi.", processedCount);

        } catch (Exception e) {
            log.error("Batch otomatik yükleme işlemi sırasında hata: ", e);
        }
    }

    private ResponseMessage executeAutoTopUp(AutoTopUpConfig config, BigDecimal currentBalance) {
        AutoTopUpLog.AutoTopUpLogBuilder logBuilder = AutoTopUpLog.builder()
                .config(config)
                .timestamp(LocalDateTime.now())
                .amount(config.getAmount());

        try {
            Wallet wallet = config.getWallet();
            BusCard busCard = config.getBusCard();

            // Cüzdan bakiyesi kontrolü
            if (wallet.getBalance().compareTo(config.getAmount()) < 0) {
                String errorMsg = "Cüzdan bakiyesi yetersiz. Mevcut: " + wallet.getBalance() +
                        " TL, Gerekli: " + config.getAmount() + " TL";

                AutoTopUpLog failLog = logBuilder
                        .success(false)
                        .failureReason(errorMsg)
                        .build();

                autoTopUpLogRepository.save(failLog);

                log.warn("Otomatik yükleme başarısız - Yetersiz bakiye: ConfigId={}, Kullanıcı={}",
                        config.getId(), config.getUser().getUsername());

                return new ResponseMessage(errorMsg, false);
            }

            // Bakiyeleri kaydet (log için)
            BigDecimal walletBalanceBefore = wallet.getBalance();
            BigDecimal cardBalanceBefore = currentBalance;

            // Cüzdandan para çek
            BigDecimal walletBalanceAfter = wallet.getBalance().subtract(config.getAmount());
            wallet.setBalance(walletBalanceAfter);
            walletRepository.save(wallet);

            // Karta para yükle
            BigDecimal cardBalanceAfter = busCard.getBalance().add(config.getAmount());
            busCard.setBalance(cardBalanceAfter);
            busCardRepository.save(busCard);


            // Cüzdan işlem kaydı oluştur
            WalletTransaction walletTransaction = WalletTransaction.builder()
                    .wallet(wallet)
                    .amount(config.getAmount())
                    .type(TransactionType.AUTO_TOPUP)
                    .description("Otomatik yükleme: " + busCard.getCardNumber())
                    .timestamp(LocalDateTime.now())
                    .build();

            walletTransactionRepository.save(walletTransaction);

            // Başarılı log kaydı
            AutoTopUpLog successLog = logBuilder
                    .success(true)
                    .failureReason(null)
                    .build();

            autoTopUpLogRepository.save(successLog);

            // Config güncelle
            config.setLastTopUpAt(LocalDateTime.now());
            autoTopUpConfigRepository.save(config);

            log.info("Otomatik yükleme başarılı: Kart={}, Tutar={}, Kullanıcı={}, Yeni Kart Bakiyesi={}, Yeni Cüzdan Bakiyesi={}",
                    busCard.getCardNumber(), config.getAmount(), config.getUser().getUsername(),
                    busCard.getBalance(), wallet.getBalance());

            return new ResponseMessage(
                    String.format("Otomatik yükleme başarılı. %s TL yüklendi. Yeni bakiye: %s TL",
                            config.getAmount(), busCard.getBalance()),
                    true
            );

        } catch (Exception e) {
            // Hata durumunda log kaydet
            AutoTopUpLog errorLog = logBuilder
                    .success(false)
                    .failureReason("Sistem hatası: " + e.getMessage())
                    .build();

            autoTopUpLogRepository.save(errorLog);

            log.error("Otomatik yükleme sırasında hata: ConfigId={}", config.getId(), e);

            return new ResponseMessage("Otomatik yükleme başarısız: " + e.getMessage(), false);
        }
    }

    @Override
    public List<AutoTopUpLogDTO> getAutoTopUpLogs(String username) {
        try {
            User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

            List<AutoTopUpLog> logs = autoTopUpLogRepository.findByConfigUserOrderByTimestampDesc(user);

            return logs.stream().map(this::mapToAutoTopUpLogDTO).collect(Collectors.toList());

        } catch (Exception e) {
            log.error("Otomatik yükleme logları getirilirken hata: ", e);
            return new ArrayList<>();
        }
    }

    @Override
    public List<AutoTopUpLogDTO> getAutoTopUpLogsByConfig(String username, Long configId) {
        try {
            User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

            AutoTopUpConfig config = autoTopUpConfigRepository.findByIdAndUser(configId, user)
                    .orElseThrow(AutoTopUpConfigNotFoundException::new);

            List<AutoTopUpLog> logs = autoTopUpLogRepository.findByConfigOrderByTimestampDesc(config);

            return logs.stream().map(this::mapToAutoTopUpLogDTO).collect(Collectors.toList());

        } catch (Exception e) {
            log.error("Konfigürasyon logları getirilirken hata: ", e);
            return new ArrayList<>();
        }
    }

    @Override
    public AutoTopUpStatsDTO getAutoTopUpStats(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        List<AutoTopUpConfig> allConfigs = autoTopUpConfigRepository.findByUser(user);
        List<AutoTopUpLog> allLogs = autoTopUpLogRepository.findByConfigUserOrderByTimestampDesc(user);

        int activeConfigs = (int) allConfigs.stream().mapToLong(c -> c.isActive() ? 1 : 0).sum();
        int inactiveConfigs = allConfigs.size() - activeConfigs;

        int successfulTopUps = (int) allLogs.stream().mapToLong(l -> l.isSuccess() ? 1 : 0).sum();
        int failedTopUps = allLogs.size() - successfulTopUps;

        BigDecimal totalAmount = allLogs.stream()
                .filter(AutoTopUpLog::isSuccess)
                .map(AutoTopUpLog::getAmount)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        LocalDateTime lastTopUp = allLogs.stream()
                .filter(AutoTopUpLog::isSuccess)
                .map(AutoTopUpLog::getTimestamp)
                .max(LocalDateTime::compareTo)
                .orElse(null);

        LocalDateTime firstTopUp = allLogs.stream()
                .filter(AutoTopUpLog::isSuccess)
                .map(AutoTopUpLog::getTimestamp)
                .min(LocalDateTime::compareTo)
                .orElse(null);

        return AutoTopUpStatsDTO.builder()
                .userId(user.getId())
                .username(username)
                .totalActiveConfigs(activeConfigs)
                .totalInactiveConfigs(inactiveConfigs)
                .totalSuccessfulTopUps(successfulTopUps)
                .totalFailedTopUps(failedTopUps)
                .totalAmountTopUpped(totalAmount)
                .lastTopUpDate(lastTopUp)
                .firstTopUpDate(firstTopUp)
                .build();
    }

    @Override
    public boolean hasActiveAutoTopUpForCard(Long busCardId) {
        try {
            BusCard busCard = busCardRepository.findById(busCardId).orElse(null);
            if (busCard == null) return false;

            return autoTopUpConfigRepository.existsByBusCardAndActive(busCard, true);
        } catch (Exception e) {
            log.error("Kart otomatik yükleme kontrolü sırasında hata: ", e);
            return false;
        }
    }

    @Override
    public boolean canProcessAutoTopUp(Long busCardId, BigDecimal currentBalance) {
        try {
            BusCard busCard = busCardRepository.findById(busCardId).orElse(null);
            if (busCard == null) return false;

            Optional<AutoTopUpConfig> configOpt = autoTopUpConfigRepository.findByBusCardAndActive(busCard, true);
            if (configOpt.isEmpty()) return false;

            AutoTopUpConfig config = configOpt.get();

            // Eşik kontrolü
            if (currentBalance.compareTo(config.getThreshold()) > 0) return false;

            Wallet wallet = config.getWallet();
            return wallet != null
                    && wallet.getBalance() != null
                    && wallet.getBalance().compareTo(config.getAmount()) >= 0;


        } catch (Exception e) {
            log.error("Otomatik yükleme kontrol sırasında hata: ", e);
            return false;
        }
    }

    // Mapping methods
    private AutoTopUpConfigDTO mapToAutoTopUpConfigDTO(AutoTopUpConfig config) {
        BusCard busCard = config.getBusCard();
        User user = config.getUser();

        // Bu konfigürasyon için toplam işlem sayısı ve tutarı
        List<AutoTopUpLog> logs = autoTopUpLogRepository.findByConfigAndSuccess(config, true);
        int totalTopUpCount = logs.size();
        BigDecimal totalTopUpAmount = logs.stream()
                .map(AutoTopUpLog::getAmount)
                .filter(Objects::nonNull)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        // Kart takma adı (varsa)
        String cardAlias = null;
        if (user.getCardNicknames() != null && user.getCardNicknames().containsKey(busCard)) {
            cardAlias = user.getCardNicknames().get(busCard);
        }

        return AutoTopUpConfigDTO.builder()
                .id(config.getId())
                .busCardId(busCard.getId())
                .busCardNumber(busCard.getCardNumber())
                .busCardAlias(cardAlias)
                .threshold(config.getThreshold())
                .amount(config.getAmount())
                .active(config.isActive())
                .lastTopUpAt(config.getLastTopUpAt())
                .createdAt(config.getCreatedAt())
                .totalTopUpCount(totalTopUpCount)
                .totalTopUpAmount(totalTopUpAmount)
                .build();
    }

    private AutoTopUpLogDTO mapToAutoTopUpLogDTO(AutoTopUpLog log) {
        AutoTopUpConfig config = log.getConfig();
        BusCard busCard = config.getBusCard();

        return AutoTopUpLogDTO.builder()
                .id(log.getId())
                .configId(config.getId())
                .busCardNumber(busCard.getCardNumber())
                .timestamp(log.getTimestamp())
                .amount(log.getAmount())
                .success(log.isSuccess())
                .failureReason(log.getFailureReason())
                .build();
    }
}