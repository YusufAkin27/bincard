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
        log.debug("AutoTopUpManager.getAutoTopUpConfigs - Method called for user: {}", username);
        try {
            User user = userRepository.findByUserNumber(username)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.getAutoTopUpConfigs - User not found: {}", username);
                        return new UserNotFoundException();
                    });

            List<AutoTopUpConfig> configs = autoTopUpConfigRepository.findByUserAndActiveOrderByCreatedAtDesc(user, true);
            log.info("AutoTopUpManager.getAutoTopUpConfigs - Found {} configs for user: {}", configs.size(), username);

            return configs.stream().map(this::mapToAutoTopUpConfigDTO).collect(Collectors.toList());
        } catch (UserNotFoundException e) {
            log.error("AutoTopUpManager.getAutoTopUpConfigs - User not found: {}", username);
            throw e;
        } catch (Exception e) {
            log.error("AutoTopUpManager.getAutoTopUpConfigs - Unexpected error for user: {}", username, e);
            throw e;
        }
    }

    @Override
    @Transactional
    public ResponseMessage addAutoTopUpConfig(String username, AutoTopUpConfigRequest configRequest)
            throws UserNotFoundException, BusCardNotFoundException, WalletIsEmptyException {
        log.debug("AutoTopUpManager.addAutoTopUpConfig - Method called for user: {}, BusCardId: {}, Threshold: {}, Amount: {}", 
                username, configRequest.getBusCard(), configRequest.getThreshold(), configRequest.getAmount());
        try {
            User user = userRepository.findByUserNumber(username)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.addAutoTopUpConfig - User not found: {}", username);
                        return new UserNotFoundException();
                    });

            BusCard busCard = busCardRepository.findById(configRequest.getBusCard())
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.addAutoTopUpConfig - BusCard not found: {}", configRequest.getBusCard());
                        return new BusCardNotFoundException();
                    });

            log.debug("AutoTopUpManager.addAutoTopUpConfig - User and BusCard found");

            // Cüzdan kontrolü
            Wallet wallet = user.getWallet();
            if (wallet == null) {
                log.warn("AutoTopUpManager.addAutoTopUpConfig - Wallet not found for user: {}", username);
                throw new WalletIsEmptyException();
            }

            // Bu kart için zaten aktif bir otomatik yükleme var mı kontrol et
            boolean hasActiveConfig = autoTopUpConfigRepository.existsByBusCardAndActive(busCard, true);
            if (hasActiveConfig) {
                log.warn("AutoTopUpManager.addAutoTopUpConfig - Active config already exists for BusCardId: {}", busCard.getId());
                return new ResponseMessage("Bu kart için zaten aktif bir otomatik yükleme konfigürasyonu bulunmaktadır.", false);
            }

            // Minimum cüzdan bakiyesi kontrolü
            if (wallet.getBalance() == null || wallet.getBalance().compareTo(configRequest.getAmount()) < 0) {
                log.warn("AutoTopUpManager.addAutoTopUpConfig - Insufficient wallet balance: {} < {} for user: {}", 
                        wallet.getBalance(), configRequest.getAmount(), username);
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

            // Konfigürasyon oluşturulduğunda log kaydı
            AutoTopUpLog configLog = AutoTopUpLog.builder()
                    .config(autoTopUpConfig)
                    .timestamp(LocalDateTime.now())
                    .amount(BigDecimal.ZERO) // Konfigürasyon işlemi için amount=0
                    .success(true)
                    .failureReason("Konfigürasyon oluşturuldu: Eşik=" + configRequest.getThreshold() + 
                            " TL, Yükleme Tutarı=" + configRequest.getAmount() + " TL")
                    .build();
            autoTopUpLogRepository.save(configLog);

            log.info("AutoTopUpManager.addAutoTopUpConfig - Config created: ID={}, User={}, Card={}, Threshold={}, Amount={}",
                    autoTopUpConfig.getId(), username, busCard.getCardNumber(), configRequest.getThreshold(), configRequest.getAmount());

            return new ResponseMessage("Otomatik yükleme konfigürasyonu başarıyla oluşturuldu.", true);
        } catch (UserNotFoundException | BusCardNotFoundException | WalletIsEmptyException e) {
            log.error("AutoTopUpManager.addAutoTopUpConfig - Error for user: {}", username, e);
            throw e;
        } catch (Exception e) {
            log.error("AutoTopUpManager.addAutoTopUpConfig - Unexpected error for user: {}", username, e);
            throw e;
        }
    }

    @Override
    @Transactional
    public ResponseMessage updateAutoTopUpConfig(String username, Long configId, AutoTopUpConfigRequest configRequest)
            throws UserNotFoundException, AutoTopUpConfigNotFoundException, BusCardNotFoundException {
        log.debug("AutoTopUpManager.updateAutoTopUpConfig - Method called for user: {}, ConfigId: {}, Threshold: {}, Amount: {}", 
                username, configId, configRequest.getThreshold(), configRequest.getAmount());
        try {
            User user = userRepository.findByUserNumber(username)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.updateAutoTopUpConfig - User not found: {}", username);
                        return new UserNotFoundException();
                    });

            BusCard busCard = busCardRepository.findById(configRequest.getBusCard())
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.updateAutoTopUpConfig - BusCard not found: {}", configRequest.getBusCard());
                        return new BusCardNotFoundException();
                    });

            AutoTopUpConfig config = autoTopUpConfigRepository.findByIdAndUser(configId, user)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.updateAutoTopUpConfig - Config not found: {} for user: {}", configId, username);
                        return new AutoTopUpConfigNotFoundException();
                    });

            log.debug("AutoTopUpManager.updateAutoTopUpConfig - Config found: ID={}", config.getId());

            // Cüzdan bakiyesi kontrolü
            Wallet wallet = user.getWallet();
            if (wallet != null && wallet.getBalance() != null && wallet.getBalance().compareTo(configRequest.getAmount()) < 0) {
                log.warn("AutoTopUpManager.updateAutoTopUpConfig - Insufficient wallet balance: {} < {} for user: {}", 
                        wallet.getBalance(), configRequest.getAmount(), username);
                return new ResponseMessage("Cüzdan bakiyeniz yeni otomatik yükleme tutarından az.", false);
            }

            BigDecimal oldThreshold = config.getThreshold();
            BigDecimal oldAmount = config.getAmount();
            
            config.setThreshold(configRequest.getThreshold());
            config.setAmount(configRequest.getAmount());
            config.setBusCard(busCard);

            autoTopUpConfigRepository.save(config);

            // Konfigürasyon güncellendiğinde log kaydı
            AutoTopUpLog updateLog = AutoTopUpLog.builder()
                    .config(config)
                    .timestamp(LocalDateTime.now())
                    .amount(BigDecimal.ZERO) // Konfigürasyon işlemi için amount=0
                    .success(true)
                    .failureReason("Konfigürasyon güncellendi: Eski Eşik=" + oldThreshold + 
                            " TL, Yeni Eşik=" + configRequest.getThreshold() + 
                            " TL, Eski Tutar=" + oldAmount + 
                            " TL, Yeni Tutar=" + configRequest.getAmount() + " TL")
                    .build();
            autoTopUpLogRepository.save(updateLog);

            log.info("AutoTopUpManager.updateAutoTopUpConfig - Config updated: ID={}, User={}, New Threshold={}, New Amount={}",
                    configId, username, configRequest.getThreshold(), configRequest.getAmount());

            return new ResponseMessage("Otomatik yükleme konfigürasyonu başarıyla güncellendi.", true);
        } catch (UserNotFoundException | AutoTopUpConfigNotFoundException | BusCardNotFoundException e) {
            log.error("AutoTopUpManager.updateAutoTopUpConfig - Error for user: {}, ConfigId: {}", username, configId, e);
            throw e;
        } catch (Exception e) {
            log.error("AutoTopUpManager.updateAutoTopUpConfig - Unexpected error for user: {}, ConfigId: {}", username, configId, e);
            throw e;
        }
    }

    @Override
    @Transactional
    public ResponseMessage deleteAutoTopUpConfig(String username, Long configId)
            throws AutoTopUpConfigNotFoundException, UserNotFoundException {
        log.debug("AutoTopUpManager.deleteAutoTopUpConfig - Method called for user: {}, ConfigId: {}", username, configId);
        try {
            User user = userRepository.findByUserNumber(username)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.deleteAutoTopUpConfig - User not found: {}", username);
                        return new UserNotFoundException();
                    });

            AutoTopUpConfig config = autoTopUpConfigRepository.findByIdAndUser(configId, user)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.deleteAutoTopUpConfig - Config not found: {} for user: {}", configId, username);
                        return new AutoTopUpConfigNotFoundException();
                    });

            config.setActive(false);
            autoTopUpConfigRepository.save(config);

            // Konfigürasyon silindiğinde (deaktive edildiğinde) log kaydı
            AutoTopUpLog deleteLog = AutoTopUpLog.builder()
                    .config(config)
                    .timestamp(LocalDateTime.now())
                    .amount(BigDecimal.ZERO) // Konfigürasyon işlemi için amount=0
                    .success(true)
                    .failureReason("Konfigürasyon deaktive edildi (silindi)")
                    .build();
            autoTopUpLogRepository.save(deleteLog);

            log.info("AutoTopUpManager.deleteAutoTopUpConfig - Config deactivated: ID={}, User={}", configId, username);

            return new ResponseMessage("Otomatik yükleme konfigürasyonu başarıyla kapatıldı.", true);
        } catch (AutoTopUpConfigNotFoundException | UserNotFoundException e) {
            log.error("AutoTopUpManager.deleteAutoTopUpConfig - Error for user: {}, ConfigId: {}", username, configId, e);
            throw e;
        } catch (Exception e) {
            log.error("AutoTopUpManager.deleteAutoTopUpConfig - Unexpected error for user: {}, ConfigId: {}", username, configId, e);
            throw e;
        }
    }

    @Override
    @Transactional
    public ResponseMessage toggleAutoTopUpConfig(String username, Long configId)
            throws UserNotFoundException, AutoTopUpConfigNotFoundException {
        log.debug("AutoTopUpManager.toggleAutoTopUpConfig - Method called for user: {}, ConfigId: {}", username, configId);
        try {
            User user = userRepository.findByUserNumber(username)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.toggleAutoTopUpConfig - User not found: {}", username);
                        return new UserNotFoundException();
                    });

            AutoTopUpConfig config = autoTopUpConfigRepository.findByIdAndUser(configId, user)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.toggleAutoTopUpConfig - Config not found: {} for user: {}", configId, username);
                        return new AutoTopUpConfigNotFoundException();
                    });

            boolean oldStatus = config.isActive();
            config.setActive(!config.isActive());
            autoTopUpConfigRepository.save(config);

            // Konfigürasyon durumu değiştiğinde log kaydı
            String status = config.isActive() ? "aktive" : "deaktive";
            AutoTopUpLog toggleLog = AutoTopUpLog.builder()
                    .config(config)
                    .timestamp(LocalDateTime.now())
                    .amount(BigDecimal.ZERO) // Konfigürasyon işlemi için amount=0
                    .success(true)
                    .failureReason("Konfigürasyon durumu değiştirildi: " + (oldStatus ? "Aktif" : "Pasif") + 
                            " → " + (config.isActive() ? "Aktif" : "Pasif"))
                    .build();
            autoTopUpLogRepository.save(toggleLog);

            log.info("AutoTopUpManager.toggleAutoTopUpConfig - Config toggled: ID={}, User={}, Old Status={}, New Status={}", 
                    configId, username, oldStatus, config.isActive());

            return new ResponseMessage("Otomatik yükleme konfigürasyonu " + status + " edildi.", true);
        } catch (UserNotFoundException | AutoTopUpConfigNotFoundException e) {
            log.error("AutoTopUpManager.toggleAutoTopUpConfig - Error for user: {}, ConfigId: {}", username, configId, e);
            throw e;
        } catch (Exception e) {
            log.error("AutoTopUpManager.toggleAutoTopUpConfig - Unexpected error for user: {}, ConfigId: {}", username, configId, e);
            throw e;
        }
    }

    @Override
    @Transactional
    public ResponseMessage processAutoTopUp(Long busCardId, BigDecimal currentBalance) {
        log.debug("AutoTopUpManager.processAutoTopUp - Method called for BusCardId: {}, CurrentBalance: {}", 
                busCardId, currentBalance);
        try {
            BusCard busCard = busCardRepository.findById(busCardId)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.processAutoTopUp - BusCard not found: {}", busCardId);
                        return new BusCardNotFoundException();
                    });

            log.debug("AutoTopUpManager.processAutoTopUp - BusCard found: {}", busCard.getCardNumber());

            // Eğer currentBalance null ise, kartın mevcut bakiyesini kullan
            if (currentBalance == null) {
                currentBalance = busCard.getBalance();
                log.debug("AutoTopUpManager.processAutoTopUp - CurrentBalance was null, using card balance: {}", currentBalance);
            }

            // Bu kart için aktif otomatik yükleme konfigürasyonu var mı?
            Optional<AutoTopUpConfig> configOpt = autoTopUpConfigRepository.findByBusCardAndActive(busCard, true);

            if (configOpt.isEmpty()) {
                log.warn("AutoTopUpManager.processAutoTopUp - No active config found for BusCardId: {}", busCardId);
                return new ResponseMessage("Bu kart için aktif otomatik yükleme konfigürasyonu bulunamadı.", false);
            }

            AutoTopUpConfig config = configOpt.get();
            log.debug("AutoTopUpManager.processAutoTopUp - Config found: ID={}, Threshold={}, Amount={}", 
                    config.getId(), config.getThreshold(), config.getAmount());

            // Eşik kontrolü
            if (currentBalance == null || currentBalance.compareTo(config.getThreshold()) > 0) {
                log.debug("AutoTopUpManager.processAutoTopUp - Card balance ({}) is above threshold ({}), no top-up needed",
                        currentBalance, config.getThreshold());
                return new ResponseMessage("Kart bakiyesi eşik değerinden yüksek, otomatik yükleme gerekli değil.", true);
            }

            log.info("AutoTopUpManager.processAutoTopUp - Processing auto top-up for BusCardId: {}, CurrentBalance: {}, Threshold: {}", 
                    busCardId, currentBalance, config.getThreshold());
            return executeAutoTopUp(config, currentBalance);

        } catch (BusCardNotFoundException e) {
            log.error("AutoTopUpManager.processAutoTopUp - BusCard not found: {}", busCardId);
            return new ResponseMessage("Belirtilen kart bulunamadı.", false);
        } catch (Exception e) {
            log.error("AutoTopUpManager.processAutoTopUp - Unexpected error for BusCardId: {}", busCardId, e);
            return new ResponseMessage("Otomatik yükleme işlemi başarısız: " + e.getMessage(), false);
        }
    }

    @Override
    @Transactional
    public ResponseMessage processAutoTopUpForUser(String username) {
        log.debug("AutoTopUpManager.processAutoTopUpForUser - Method called for user: {}", username);
        try {
            User user = userRepository.findByUserNumber(username)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.processAutoTopUpForUser - User not found: {}", username);
                        return new UserNotFoundException();
                    });

            log.debug("AutoTopUpManager.processAutoTopUpForUser - User found: ID={}", user.getId());

            List<AutoTopUpConfig> activeConfigs = autoTopUpConfigRepository.findByUserAndActive(user, true);

            if (activeConfigs.isEmpty()) {
                log.warn("AutoTopUpManager.processAutoTopUpForUser - No active configs found for user: {}", username);
                return new ResponseMessage("Aktif otomatik yükleme konfigürasyonu bulunamadı.", false);
            }

            log.info("AutoTopUpManager.processAutoTopUpForUser - Processing {} active configs for user: {}", 
                    activeConfigs.size(), username);

            int successCount = 0;
            int totalCount = activeConfigs.size();

            for (AutoTopUpConfig config : activeConfigs) {
                try {
                    BusCard busCard = config.getBusCard();
                    BigDecimal currentBalance = busCard.getBalance();

                    if (currentBalance != null && currentBalance.compareTo(config.getThreshold()) <= 0) {
                        log.debug("AutoTopUpManager.processAutoTopUpForUser - Processing config ID={} for BusCardId={}, Balance={}, Threshold={}", 
                                config.getId(), busCard.getId(), currentBalance, config.getThreshold());
                        ResponseMessage result = executeAutoTopUp(config, currentBalance);
                        if (result.isSuccess()) {
                            successCount++;
                            log.debug("AutoTopUpManager.processAutoTopUpForUser - Success for config ID={}", config.getId());
                        } else {
                            log.warn("AutoTopUpManager.processAutoTopUpForUser - Failed for config ID={}: {}", 
                                    config.getId(), result.getMessage());
                        }
                    } else {
                        log.debug("AutoTopUpManager.processAutoTopUpForUser - Skipping config ID={}, balance above threshold", config.getId());
                    }
                } catch (Exception e) {
                    log.error("AutoTopUpManager.processAutoTopUpForUser - Error processing config ID={} for user: {}", 
                            config.getId(), username, e);
                }
            }

            log.info("AutoTopUpManager.processAutoTopUpForUser - Completed: {}/{} successful for user: {}", 
                    successCount, totalCount, username);

            return new ResponseMessage(
                    String.format("Otomatik yükleme işlemi tamamlandı. %d/%d konfigürasyon başarılı.", successCount, totalCount),
                    successCount > 0
            );

        } catch (UserNotFoundException e) {
            log.error("AutoTopUpManager.processAutoTopUpForUser - User not found: {}", username);
            return new ResponseMessage("Kullanıcı bulunamadı.", false);
        } catch (Exception e) {
            log.error("AutoTopUpManager.processAutoTopUpForUser - Unexpected error for user: {}", username, e);
            return new ResponseMessage("Otomatik yükleme işlemi başarısız: " + e.getMessage(), false);
        }
    }

    @Override
    @Transactional
    public void processAllPendingAutoTopUps() {
        log.debug("AutoTopUpManager.processAllPendingAutoTopUps - Method called");
        try {
            List<AutoTopUpConfig> allActiveConfigs = autoTopUpConfigRepository.findByActive(true);

            log.info("AutoTopUpManager.processAllPendingAutoTopUps - Checking {} active auto top-up configurations", allActiveConfigs.size());

            int processedCount = 0;
            int failedCount = 0;

            for (AutoTopUpConfig config : allActiveConfigs) {
                try {
                    BusCard busCard = config.getBusCard();
                    if (busCard == null) {
                        log.warn("AutoTopUpManager.processAllPendingAutoTopUps - BusCard is null for config ID: {}", config.getId());
                        failedCount++;
                        continue;
                    }

                    BigDecimal currentBalance = busCard.getBalance();

                    if (currentBalance != null && config.getThreshold() != null &&
                            currentBalance.compareTo(config.getThreshold()) <= 0) {

                        log.debug("AutoTopUpManager.processAllPendingAutoTopUps - Processing config ID={}, BusCardId={}, Balance={}, Threshold={}", 
                                config.getId(), busCard.getId(), currentBalance, config.getThreshold());

                        ResponseMessage result = executeAutoTopUp(config, currentBalance);
                        if (result.isSuccess()) {
                            processedCount++;
                            log.debug("AutoTopUpManager.processAllPendingAutoTopUps - Success for config ID={}", config.getId());
                        } else {
                            failedCount++;
                            log.warn("AutoTopUpManager.processAllPendingAutoTopUps - Failed for config ID={}: {}", 
                                    config.getId(), result.getMessage());
                        }
                    } else {
                        log.debug("AutoTopUpManager.processAllPendingAutoTopUps - Skipping config ID={}, balance above threshold", config.getId());
                    }

                } catch (Exception e) {
                    failedCount++;
                    log.error("AutoTopUpManager.processAllPendingAutoTopUps - Error processing config ID={}", config.getId(), e);
                }
            }

            log.info("AutoTopUpManager.processAllPendingAutoTopUps - Batch process completed. Success: {}, Failed: {}, Total: {}", 
                    processedCount, failedCount, allActiveConfigs.size());

        } catch (Exception e) {
            log.error("AutoTopUpManager.processAllPendingAutoTopUps - Unexpected error in batch process", e);
        }
    }

    private ResponseMessage executeAutoTopUp(AutoTopUpConfig config, BigDecimal currentBalance) {
        log.debug("AutoTopUpManager.executeAutoTopUp - Method called for ConfigId: {}, Amount: {}, CurrentBalance: {}", 
                config.getId(), config.getAmount(), currentBalance);
        
        AutoTopUpLog.AutoTopUpLogBuilder logBuilder = AutoTopUpLog.builder()
                .config(config)
                .timestamp(LocalDateTime.now())
                .amount(config.getAmount());

        try {
            Wallet wallet = config.getWallet();
            BusCard busCard = config.getBusCard();

            if (wallet == null) {
                log.error("AutoTopUpManager.executeAutoTopUp - Wallet is null for ConfigId: {}", config.getId());
                AutoTopUpLog failLog = logBuilder
                        .success(false)
                        .failureReason("Cüzdan bulunamadı")
                        .build();
                autoTopUpLogRepository.save(failLog);
                return new ResponseMessage("Cüzdan bulunamadı.", false);
            }

            if (busCard == null) {
                log.error("AutoTopUpManager.executeAutoTopUp - BusCard is null for ConfigId: {}", config.getId());
                AutoTopUpLog failLog = logBuilder
                        .success(false)
                        .failureReason("Kart bulunamadı")
                        .build();
                autoTopUpLogRepository.save(failLog);
                return new ResponseMessage("Kart bulunamadı.", false);
            }

            // Cüzdan bakiyesi kontrolü
            if (wallet.getBalance() == null || wallet.getBalance().compareTo(config.getAmount()) < 0) {
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
            log.debug("AutoTopUpManager.executeAutoTopUp - Before: Wallet={}, Card={}, Amount={}", 
                    walletBalanceBefore, cardBalanceBefore, config.getAmount());

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

            log.info("AutoTopUpManager.executeAutoTopUp - Success: ConfigId={}, Card={}, Amount={}, User={}, New Card Balance={}, New Wallet Balance={}",
                    config.getId(), busCard.getCardNumber(), config.getAmount(), config.getUser().getUsername(),
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

            log.error("AutoTopUpManager.executeAutoTopUp - Error for ConfigId={}", config.getId(), e);

            return new ResponseMessage("Otomatik yükleme başarısız: " + e.getMessage(), false);
        }
    }

    @Override
    public List<AutoTopUpLogDTO> getAutoTopUpLogs(String username) {
        log.debug("AutoTopUpManager.getAutoTopUpLogs - Method called for user: {}", username);
        try {
            User user = userRepository.findByUserNumber(username)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.getAutoTopUpLogs - User not found: {}", username);
                        return new UserNotFoundException();
                    });

            List<AutoTopUpLog> logs = autoTopUpLogRepository.findByConfigUserOrderByTimestampDesc(user);
            log.info("AutoTopUpManager.getAutoTopUpLogs - Found {} logs for user: {}", logs.size(), username);

            return logs.stream().map(this::mapToAutoTopUpLogDTO).collect(Collectors.toList());

        } catch (UserNotFoundException e) {
            log.error("AutoTopUpManager.getAutoTopUpLogs - User not found: {}", username);
            return new ArrayList<>();
        } catch (Exception e) {
            log.error("AutoTopUpManager.getAutoTopUpLogs - Unexpected error for user: {}", username, e);
            return new ArrayList<>();
        }
    }

    @Override
    public List<AutoTopUpLogDTO> getAutoTopUpLogsByConfig(String username, Long configId) {
        log.debug("AutoTopUpManager.getAutoTopUpLogsByConfig - Method called for user: {}, ConfigId: {}", username, configId);
        try {
            User user = userRepository.findByUserNumber(username)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.getAutoTopUpLogsByConfig - User not found: {}", username);
                        return new UserNotFoundException();
                    });

            AutoTopUpConfig config = autoTopUpConfigRepository.findByIdAndUser(configId, user)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.getAutoTopUpLogsByConfig - Config not found: {} for user: {}", configId, username);
                        return new AutoTopUpConfigNotFoundException();
                    });

            List<AutoTopUpLog> logs = autoTopUpLogRepository.findByConfigOrderByTimestampDesc(config);
            log.info("AutoTopUpManager.getAutoTopUpLogsByConfig - Found {} logs for ConfigId: {}, User: {}", 
                    logs.size(), configId, username);

            return logs.stream().map(this::mapToAutoTopUpLogDTO).collect(Collectors.toList());

        } catch (UserNotFoundException | AutoTopUpConfigNotFoundException e) {
            log.error("AutoTopUpManager.getAutoTopUpLogsByConfig - Error for user: {}, ConfigId: {}", username, configId, e);
            return new ArrayList<>();
        } catch (Exception e) {
            log.error("AutoTopUpManager.getAutoTopUpLogsByConfig - Unexpected error for user: {}, ConfigId: {}", username, configId, e);
            return new ArrayList<>();
        }
    }

    @Override
    public AutoTopUpStatsDTO getAutoTopUpStats(String username) throws UserNotFoundException {
        log.debug("AutoTopUpManager.getAutoTopUpStats - Method called for user: {}", username);
        try {
            User user = userRepository.findByUserNumber(username)
                    .orElseThrow(() -> {
                        log.warn("AutoTopUpManager.getAutoTopUpStats - User not found: {}", username);
                        return new UserNotFoundException();
                    });

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

            AutoTopUpStatsDTO stats = AutoTopUpStatsDTO.builder()
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

            log.info("AutoTopUpManager.getAutoTopUpStats - Stats retrieved for user: {}, Active Configs: {}, Successful TopUps: {}", 
                    username, activeConfigs, successfulTopUps);
            return stats;
        } catch (UserNotFoundException e) {
            log.error("AutoTopUpManager.getAutoTopUpStats - User not found: {}", username);
            throw e;
        } catch (Exception e) {
            log.error("AutoTopUpManager.getAutoTopUpStats - Unexpected error for user: {}", username, e);
            throw new UserNotFoundException();
        }
    }

    @Override
    public boolean hasActiveAutoTopUpForCard(Long busCardId) {
        log.debug("AutoTopUpManager.hasActiveAutoTopUpForCard - Method called for BusCardId: {}", busCardId);
        try {
            BusCard busCard = busCardRepository.findById(busCardId).orElse(null);
            if (busCard == null) {
                log.warn("AutoTopUpManager.hasActiveAutoTopUpForCard - BusCard not found: {}", busCardId);
                return false;
            }

            boolean hasActive = autoTopUpConfigRepository.existsByBusCardAndActive(busCard, true);
            log.debug("AutoTopUpManager.hasActiveAutoTopUpForCard - Result: {} for BusCardId: {}", hasActive, busCardId);
            return hasActive;
        } catch (Exception e) {
            log.error("AutoTopUpManager.hasActiveAutoTopUpForCard - Error for BusCardId: {}", busCardId, e);
            return false;
        }
    }

    @Override
    public boolean canProcessAutoTopUp(Long busCardId, BigDecimal currentBalance) {
        log.debug("AutoTopUpManager.canProcessAutoTopUp - Method called for BusCardId: {}, CurrentBalance: {}", 
                busCardId, currentBalance);
        try {
            BusCard busCard = busCardRepository.findById(busCardId).orElse(null);
            if (busCard == null) {
                log.warn("AutoTopUpManager.canProcessAutoTopUp - BusCard not found: {}", busCardId);
                return false;
            }

            Optional<AutoTopUpConfig> configOpt = autoTopUpConfigRepository.findByBusCardAndActive(busCard, true);
            if (configOpt.isEmpty()) {
                log.debug("AutoTopUpManager.canProcessAutoTopUp - No active config found for BusCardId: {}", busCardId);
                return false;
            }

            AutoTopUpConfig config = configOpt.get();

            // Eşik kontrolü
            if (currentBalance == null || currentBalance.compareTo(config.getThreshold()) > 0) {
                log.debug("AutoTopUpManager.canProcessAutoTopUp - Balance above threshold: {} > {} for BusCardId: {}", 
                        currentBalance, config.getThreshold(), busCardId);
                return false;
            }

            Wallet wallet = config.getWallet();
            boolean canProcess = wallet != null
                    && wallet.getBalance() != null
                    && wallet.getBalance().compareTo(config.getAmount()) >= 0;

            log.debug("AutoTopUpManager.canProcessAutoTopUp - Result: {} for BusCardId: {}, Wallet Balance: {}, Required: {}", 
                    canProcess, busCardId, wallet != null ? wallet.getBalance() : null, config.getAmount());
            return canProcess;

        } catch (Exception e) {
            log.error("AutoTopUpManager.canProcessAutoTopUp - Error for BusCardId: {}", busCardId, e);
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

    // Admin İşlemleri
    @Override
    public List<AutoTopUpConfigDTO> getAllAutoTopUpConfigs() {
        log.debug("AutoTopUpManager.getAllAutoTopUpConfigs - Method called");
        try {
            List<AutoTopUpConfig> configs = autoTopUpConfigRepository.findAll();
            log.info("AutoTopUpManager.getAllAutoTopUpConfigs - Found {} total configs", configs.size());
            return configs.stream()
                    .map(this::mapToAutoTopUpConfigDTO)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.error("AutoTopUpManager.getAllAutoTopUpConfigs - Unexpected error", e);
            return new ArrayList<>();
        }
    }

    @Override
    public List<AutoTopUpLogDTO> getAllAutoTopUpLogs() {
        log.debug("AutoTopUpManager.getAllAutoTopUpLogs - Method called");
        try {
            List<AutoTopUpLog> logs = autoTopUpLogRepository.findAll();
            log.info("AutoTopUpManager.getAllAutoTopUpLogs - Found {} total logs", logs.size());
            return logs.stream()
                    .map(this::mapToAutoTopUpLogDTO)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.error("AutoTopUpManager.getAllAutoTopUpLogs - Unexpected error", e);
            return new ArrayList<>();
        }
    }

    @Override
    public AutoTopUpStatsDTO getAllAutoTopUpStats() {
        log.debug("AutoTopUpManager.getAllAutoTopUpStats - Method called");
        try {
            List<AutoTopUpConfig> allConfigs = autoTopUpConfigRepository.findAll();
            List<AutoTopUpLog> allLogs = autoTopUpLogRepository.findAll();

            int activeConfigs = (int) allConfigs.stream().filter(AutoTopUpConfig::isActive).count();
            int inactiveConfigs = allConfigs.size() - activeConfigs;
            long successfulTopUps = allLogs.stream().filter(AutoTopUpLog::isSuccess).count();
            long failedTopUps = allLogs.size() - successfulTopUps;

            BigDecimal totalAmount = allLogs.stream()
                    .filter(AutoTopUpLog::isSuccess)
                    .map(AutoTopUpLog::getAmount)
                    .filter(Objects::nonNull)
                    .reduce(BigDecimal.ZERO, BigDecimal::add);

            LocalDateTime lastTopUp = allLogs.stream()
                    .filter(AutoTopUpLog::isSuccess)
                    .map(AutoTopUpLog::getTimestamp)
                    .filter(Objects::nonNull)
                    .max(LocalDateTime::compareTo)
                    .orElse(null);

            LocalDateTime firstTopUp = allLogs.stream()
                    .filter(AutoTopUpLog::isSuccess)
                    .map(AutoTopUpLog::getTimestamp)
                    .filter(Objects::nonNull)
                    .min(LocalDateTime::compareTo)
                    .orElse(null);

            AutoTopUpStatsDTO stats = AutoTopUpStatsDTO.builder()
                    .username("ALL_USERS")
                    .totalActiveConfigs(activeConfigs)
                    .totalInactiveConfigs(inactiveConfigs)
                    .totalSuccessfulTopUps((int) successfulTopUps)
                    .totalFailedTopUps((int) failedTopUps)
                    .totalAmountTopUpped(totalAmount)
                    .lastTopUpDate(lastTopUp)
                    .firstTopUpDate(firstTopUp)
                    .build();

            log.info("AutoTopUpManager.getAllAutoTopUpStats - Stats retrieved: Active Configs: {}, Successful TopUps: {}", 
                    activeConfigs, successfulTopUps);
            return stats;
        } catch (Exception e) {
            log.error("AutoTopUpManager.getAllAutoTopUpStats - Unexpected error", e);
            return AutoTopUpStatsDTO.builder()
                    .username("ALL_USERS")
                    .totalActiveConfigs(0)
                    .totalInactiveConfigs(0)
                    .totalSuccessfulTopUps(0)
                    .totalFailedTopUps(0)
                    .totalAmountTopUpped(BigDecimal.ZERO)
                    .build();
        }
    }
}