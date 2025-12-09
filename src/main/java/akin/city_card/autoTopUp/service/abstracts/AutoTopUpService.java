package akin.city_card.autoTopUp.service.abstracts;

import akin.city_card.autoTopUp.core.request.AutoTopUpConfigRequest;
import akin.city_card.autoTopUp.core.response.AutoTopUpConfigDTO;
import akin.city_card.autoTopUp.core.response.AutoTopUpLogDTO;
import akin.city_card.autoTopUp.core.response.AutoTopUpStatsDTO;
import akin.city_card.buscard.exceptions.BusCardNotFoundException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.AutoTopUpConfigNotFoundException;
import akin.city_card.wallet.exceptions.WalletIsEmptyException;

import java.math.BigDecimal;
import java.util.List;

public interface AutoTopUpService {

    // Kullanıcı İşlemleri
    List<AutoTopUpConfigDTO> getAutoTopUpConfigs(String username) throws UserNotFoundException;

    ResponseMessage addAutoTopUpConfig(String username, AutoTopUpConfigRequest configRequest)
            throws UserNotFoundException, BusCardNotFoundException, WalletIsEmptyException;

    ResponseMessage updateAutoTopUpConfig(String username, Long configId, AutoTopUpConfigRequest configRequest)
            throws UserNotFoundException, AutoTopUpConfigNotFoundException, BusCardNotFoundException;

    ResponseMessage deleteAutoTopUpConfig(String username, Long configId)
            throws AutoTopUpConfigNotFoundException, UserNotFoundException;

    ResponseMessage toggleAutoTopUpConfig(String username, Long configId)
            throws UserNotFoundException, AutoTopUpConfigNotFoundException;

    // Otomatik Yükleme İşlemleri
    ResponseMessage processAutoTopUp(Long busCardId, BigDecimal currentBalance);

    ResponseMessage processAutoTopUpForUser(String username);

    void processAllPendingAutoTopUps();

    // Log ve İstatistik İşlemleri
    List<AutoTopUpLogDTO> getAutoTopUpLogs(String username);

    List<AutoTopUpLogDTO> getAutoTopUpLogsByConfig(String username, Long configId);

    AutoTopUpStatsDTO getAutoTopUpStats(String username) throws UserNotFoundException;

    // Kontrol İşlemleri
    boolean hasActiveAutoTopUpForCard(Long busCardId);

    boolean canProcessAutoTopUp(Long busCardId, BigDecimal currentBalance);

    // Admin İşlemleri
    List<AutoTopUpConfigDTO> getAllAutoTopUpConfigs();

    List<AutoTopUpLogDTO> getAllAutoTopUpLogs();

    AutoTopUpStatsDTO getAllAutoTopUpStats();
}