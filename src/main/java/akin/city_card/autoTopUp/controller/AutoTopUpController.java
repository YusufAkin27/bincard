package akin.city_card.autoTopUp.controller;

import akin.city_card.autoTopUp.core.request.AutoTopUpConfigRequest;
import akin.city_card.autoTopUp.core.response.AutoTopUpConfigDTO;
import akin.city_card.autoTopUp.core.response.AutoTopUpLogDTO;
import akin.city_card.autoTopUp.core.response.AutoTopUpStatsDTO;
import akin.city_card.autoTopUp.service.abstracts.AutoTopUpService;
import akin.city_card.buscard.exceptions.BusCardNotFoundException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.AutoTopUpConfigNotFoundException;
import akin.city_card.wallet.exceptions.WalletIsEmptyException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;

@RestController
@RequestMapping("/v1/api/auto_top_up")
@RequiredArgsConstructor
@Slf4j
public class AutoTopUpController {

    private final AutoTopUpService autoTopUpService;

    /**
     * Kullanıcının otomatik yükleme konfigürasyonlarını listeleme
     */
    @GetMapping()
    public ResponseEntity<List<AutoTopUpConfigDTO>> getAutoTopUpConfigs(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        log.debug("AutoTopUpController.getAutoTopUpConfigs - Method called for user: {}", userDetails.getUsername());
        try {
            List<AutoTopUpConfigDTO> configs = autoTopUpService.getAutoTopUpConfigs(userDetails.getUsername());
            log.info("AutoTopUpController.getAutoTopUpConfigs - Success for user: {}, Config count: {}", 
                    userDetails.getUsername(), configs.size());
            return ResponseEntity.ok(configs);
        } catch (UserNotFoundException e) {
            log.error("AutoTopUpController.getAutoTopUpConfigs - User not found: {}", userDetails.getUsername());
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("AutoTopUpController.getAutoTopUpConfigs - Unexpected error for user: {}", userDetails.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Yeni otomatik yükleme konfigürasyonu oluşturma
     */
    @PostMapping()
    public ResponseEntity<ResponseMessage> addAutoTopUpConfig(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody AutoTopUpConfigRequest configRequest
    ) {
        log.debug("AutoTopUpController.addAutoTopUpConfig - Method called for user: {}, BusCardId: {}, Threshold: {}, Amount: {}", 
                userDetails.getUsername(), configRequest.getBusCard(), configRequest.getThreshold(), configRequest.getAmount());
        try {
            ResponseMessage result = autoTopUpService.addAutoTopUpConfig(userDetails.getUsername(), configRequest);
            log.info("AutoTopUpController.addAutoTopUpConfig - Success: {} for user: {}", result.isSuccess(), userDetails.getUsername());
            return ResponseEntity.status(result.isSuccess() ? HttpStatus.CREATED : HttpStatus.BAD_REQUEST).body(result);
        } catch (UserNotFoundException e) {
            log.error("AutoTopUpController.addAutoTopUpConfig - User not found: {}", userDetails.getUsername());
            return ResponseEntity.notFound().build();
        } catch (BusCardNotFoundException e) {
            log.error("AutoTopUpController.addAutoTopUpConfig - BusCard not found: {}", configRequest.getBusCard());
            return ResponseEntity.badRequest().body(new ResponseMessage("Belirtilen kart bulunamadı.", false));
        } catch (WalletIsEmptyException e) {
            log.error("AutoTopUpController.addAutoTopUpConfig - Wallet not found for user: {}", userDetails.getUsername());
            return ResponseEntity.badRequest().body(new ResponseMessage("Cüzdan bulunamadı.", false));
        } catch (Exception e) {
            log.error("AutoTopUpController.addAutoTopUpConfig - Unexpected error for user: {}", userDetails.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Otomatik yükleme konfigürasyonu oluşturulamadı: " + e.getMessage(), false));
        }
    }

    /**
     * Otomatik yükleme konfigürasyonu güncelleme
     */
    @PutMapping("/{configId}")
    public ResponseEntity<ResponseMessage> updateAutoTopUpConfig(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long configId,
            @Valid @RequestBody AutoTopUpConfigRequest configRequest
    ) {
        log.debug("AutoTopUpController.updateAutoTopUpConfig - Method called for user: {}, ConfigId: {}, Threshold: {}, Amount: {}", 
                userDetails.getUsername(), configId, configRequest.getThreshold(), configRequest.getAmount());
        try {
            ResponseMessage result = autoTopUpService.updateAutoTopUpConfig(userDetails.getUsername(), configId, configRequest);
            log.info("AutoTopUpController.updateAutoTopUpConfig - Success: {} for user: {}, ConfigId: {}", 
                    result.isSuccess(), userDetails.getUsername(), configId);
            return ResponseEntity.ok(result);
        } catch (UserNotFoundException e) {
            log.error("AutoTopUpController.updateAutoTopUpConfig - User not found: {}", userDetails.getUsername());
            return ResponseEntity.notFound().build();
        } catch (AutoTopUpConfigNotFoundException e) {
            log.error("AutoTopUpController.updateAutoTopUpConfig - Config not found: {} for user: {}", configId, userDetails.getUsername());
            return ResponseEntity.badRequest().body(new ResponseMessage("Belirtilen konfigürasyon bulunamadı.", false));
        } catch (BusCardNotFoundException e) {
            log.error("AutoTopUpController.updateAutoTopUpConfig - BusCard not found: {}", configRequest.getBusCard());
            return ResponseEntity.badRequest().body(new ResponseMessage("Belirtilen kart bulunamadı.", false));
        } catch (Exception e) {
            log.error("AutoTopUpController.updateAutoTopUpConfig - Unexpected error for user: {}, ConfigId: {}", 
                    userDetails.getUsername(), configId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Konfigürasyon güncellenemedi: " + e.getMessage(), false));
        }
    }

    /**
     * Otomatik yükleme konfigürasyonu silme (deaktive etme)
     */
    @DeleteMapping("/{configId}")
    public ResponseEntity<ResponseMessage> deleteAutoTopUpConfig(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long configId
    ) {
        log.debug("AutoTopUpController.deleteAutoTopUpConfig - Method called for user: {}, ConfigId: {}", 
                userDetails.getUsername(), configId);
        try {
            ResponseMessage result = autoTopUpService.deleteAutoTopUpConfig(userDetails.getUsername(), configId);
            log.info("AutoTopUpController.deleteAutoTopUpConfig - Success: {} for user: {}, ConfigId: {}", 
                    result.isSuccess(), userDetails.getUsername(), configId);
            return ResponseEntity.ok(result);
        } catch (UserNotFoundException e) {
            log.error("AutoTopUpController.deleteAutoTopUpConfig - User not found: {}", userDetails.getUsername());
            return ResponseEntity.notFound().build();
        } catch (AutoTopUpConfigNotFoundException e) {
            log.error("AutoTopUpController.deleteAutoTopUpConfig - Config not found: {} for user: {}", configId, userDetails.getUsername());
            return ResponseEntity.badRequest().body(new ResponseMessage("Belirtilen konfigürasyon bulunamadı.", false));
        } catch (Exception e) {
            log.error("AutoTopUpController.deleteAutoTopUpConfig - Unexpected error for user: {}, ConfigId: {}", 
                    userDetails.getUsername(), configId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Konfigürasyon silinemedi: " + e.getMessage(), false));
        }
    }

    /**
     * Otomatik yükleme konfigürasyonu aktif/pasif durumu değiştirme
     */
    @PatchMapping("/{configId}/toggle")
    public ResponseEntity<ResponseMessage> toggleAutoTopUpConfig(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long configId
    ) {
        log.debug("AutoTopUpController.toggleAutoTopUpConfig - Method called for user: {}, ConfigId: {}", 
                userDetails.getUsername(), configId);
        try {
            ResponseMessage result = autoTopUpService.toggleAutoTopUpConfig(userDetails.getUsername(), configId);
            log.info("AutoTopUpController.toggleAutoTopUpConfig - Success: {} for user: {}, ConfigId: {}", 
                    result.isSuccess(), userDetails.getUsername(), configId);
            return ResponseEntity.ok(result);
        } catch (UserNotFoundException e) {
            log.error("AutoTopUpController.toggleAutoTopUpConfig - User not found: {}", userDetails.getUsername());
            return ResponseEntity.notFound().build();
        } catch (AutoTopUpConfigNotFoundException e) {
            log.error("AutoTopUpController.toggleAutoTopUpConfig - Config not found: {} for user: {}", configId, userDetails.getUsername());
            return ResponseEntity.badRequest().body(new ResponseMessage("Belirtilen konfigürasyon bulunamadı.", false));
        } catch (Exception e) {
            log.error("AutoTopUpController.toggleAutoTopUpConfig - Unexpected error for user: {}, ConfigId: {}", 
                    userDetails.getUsername(), configId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Konfigürasyon durumu değiştirilemedi: " + e.getMessage(), false));
        }
    }

    /**
     * Manuel otomatik yükleme tetikleme (belirli bir kart için)
     */
    @PostMapping("/process/{busCardId}")
    @PreAuthorize("hasAuthority('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> processAutoTopUp(
            @PathVariable Long busCardId,
            @RequestParam(required = false) BigDecimal currentBalance
    ) {
        log.debug("AutoTopUpController.processAutoTopUp - Method called for BusCardId: {}, CurrentBalance: {}", 
                busCardId, currentBalance);
        try {
            ResponseMessage result = autoTopUpService.processAutoTopUp(busCardId, currentBalance);
            log.info("AutoTopUpController.processAutoTopUp - Success: {} for BusCardId: {}", result.isSuccess(), busCardId);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("AutoTopUpController.processAutoTopUp - Unexpected error for BusCardId: {}", busCardId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Otomatik yükleme işlemi başarısız: " + e.getMessage(), false));
        }
    }

    /**
     * Kullanıcının tüm kartları için manuel otomatik yükleme tetikleme
     */
    @PostMapping("/process")
    public ResponseEntity<ResponseMessage> processAutoTopUpForUser(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        log.debug("AutoTopUpController.processAutoTopUpForUser - Method called for user: {}", userDetails.getUsername());
        try {
            ResponseMessage result = autoTopUpService.processAutoTopUpForUser(userDetails.getUsername());
            log.info("AutoTopUpController.processAutoTopUpForUser - Success: {} for user: {}", result.isSuccess(), userDetails.getUsername());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("AutoTopUpController.processAutoTopUpForUser - Unexpected error for user: {}", userDetails.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Otomatik yükleme işlemi başarısız: " + e.getMessage(), false));
        }
    }

    /**
     * Otomatik yükleme loglarını görüntüleme
     */
    @GetMapping("/logs")
    public ResponseEntity<List<AutoTopUpLogDTO>> getAutoTopUpLogs(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        log.debug("AutoTopUpController.getAutoTopUpLogs - Method called for user: {}", userDetails.getUsername());
        try {
            List<AutoTopUpLogDTO> logs = autoTopUpService.getAutoTopUpLogs(userDetails.getUsername());
            log.info("AutoTopUpController.getAutoTopUpLogs - Success for user: {}, Log count: {}", 
                    userDetails.getUsername(), logs.size());
            return ResponseEntity.ok(logs);
        } catch (Exception e) {
            log.error("AutoTopUpController.getAutoTopUpLogs - Unexpected error for user: {}", userDetails.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Belirli bir konfigürasyon için otomatik yükleme loglarını görüntüleme
     */
    @GetMapping("/{configId}/logs")
    public ResponseEntity<List<AutoTopUpLogDTO>> getAutoTopUpLogsByConfig(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long configId
    ) {
        log.debug("AutoTopUpController.getAutoTopUpLogsByConfig - Method called for user: {}, ConfigId: {}", 
                userDetails.getUsername(), configId);
        try {
            List<AutoTopUpLogDTO> logs = autoTopUpService.getAutoTopUpLogsByConfig(userDetails.getUsername(), configId);
            log.info("AutoTopUpController.getAutoTopUpLogsByConfig - Success for user: {}, ConfigId: {}, Log count: {}", 
                    userDetails.getUsername(), configId, logs.size());
            return ResponseEntity.ok(logs);
        } catch (Exception e) {
            log.error("AutoTopUpController.getAutoTopUpLogsByConfig - Unexpected error for user: {}, ConfigId: {}", 
                    userDetails.getUsername(), configId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Kullanıcının otomatik yükleme istatistiklerini görüntüleme
     */
    @GetMapping("/stats")
    public ResponseEntity<AutoTopUpStatsDTO> getAutoTopUpStats(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        log.debug("AutoTopUpController.getAutoTopUpStats - Method called for user: {}", userDetails.getUsername());
        try {
            AutoTopUpStatsDTO stats = autoTopUpService.getAutoTopUpStats(userDetails.getUsername());
            log.info("AutoTopUpController.getAutoTopUpStats - Success for user: {}", userDetails.getUsername());
            return ResponseEntity.ok(stats);
        } catch (UserNotFoundException e) {
            log.error("AutoTopUpController.getAutoTopUpStats - User not found: {}", userDetails.getUsername());
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("AutoTopUpController.getAutoTopUpStats - Unexpected error for user: {}", userDetails.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Belirli bir kartın otomatik yükleme durumunu kontrol etme
     */
    @GetMapping("/check/{busCardId}")
    @PreAuthorize("hasAuthority('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> checkAutoTopUpStatus(
            @PathVariable Long busCardId,
            @RequestParam(required = false) BigDecimal currentBalance
    ) {
        log.debug("AutoTopUpController.checkAutoTopUpStatus - Method called for BusCardId: {}, CurrentBalance: {}", 
                busCardId, currentBalance);
        try {
            boolean hasActiveConfig = autoTopUpService.hasActiveAutoTopUpForCard(busCardId);

            if (!hasActiveConfig) {
                log.info("AutoTopUpController.checkAutoTopUpStatus - No active config for BusCardId: {}", busCardId);
                return ResponseEntity.ok(new ResponseMessage("Bu kart için aktif otomatik yükleme konfigürasyonu bulunmuyor.", false));
            }

            if (currentBalance != null) {
                boolean canProcess = autoTopUpService.canProcessAutoTopUp(busCardId, currentBalance);
                String message = canProcess
                        ? "Otomatik yükleme işlemi gerçekleştirilebilir."
                        : "Otomatik yükleme için koşullar sağlanmıyor (eşik değeri veya cüzdan bakiyesi).";
                log.info("AutoTopUpController.checkAutoTopUpStatus - Can process: {} for BusCardId: {}", canProcess, busCardId);
                return ResponseEntity.ok(new ResponseMessage(message, canProcess));
            }

            log.info("AutoTopUpController.checkAutoTopUpStatus - Active config found for BusCardId: {}", busCardId);
            return ResponseEntity.ok(new ResponseMessage("Bu kart için aktif otomatik yükleme konfigürasyonu bulunuyor.", true));

        } catch (Exception e) {
            log.error("AutoTopUpController.checkAutoTopUpStatus - Unexpected error for BusCardId: {}", busCardId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Kontrol işlemi başarısız: " + e.getMessage(), false));
        }
    }

    // ===== ADMIN ENDPOINT'LERİ =====

    /**
     * Tüm kullanıcıların otomatik yükleme konfigürasyonlarını listeleme (Admin)
     */
    @GetMapping("/admin/configs")
    @PreAuthorize("hasAuthority('AUTO_TOP_UP_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<List<AutoTopUpConfigDTO>> getAllAutoTopUpConfigs(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        log.debug("AutoTopUpController.getAllAutoTopUpConfigs - Method called by admin: {}", userDetails.getUsername());
        try {
            List<AutoTopUpConfigDTO> configs = autoTopUpService.getAllAutoTopUpConfigs();
            log.info("AutoTopUpController.getAllAutoTopUpConfigs - Success for admin: {}, Total config count: {}", 
                    userDetails.getUsername(), configs.size());
            return ResponseEntity.ok(configs);
        } catch (Exception e) {
            log.error("AutoTopUpController.getAllAutoTopUpConfigs - Unexpected error for admin: {}", userDetails.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Tüm kullanıcıların otomatik yükleme loglarını görüntüleme (SuperAdmin)
     */
    @GetMapping("/admin/logs")
    @PreAuthorize("hasAuthority('SUPERADMIN')")
    public ResponseEntity<List<AutoTopUpLogDTO>> getAllAutoTopUpLogs(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        log.debug("AutoTopUpController.getAllAutoTopUpLogs - Method called by superadmin: {}", userDetails.getUsername());
        try {
            List<AutoTopUpLogDTO> logs = autoTopUpService.getAllAutoTopUpLogs();
            log.info("AutoTopUpController.getAllAutoTopUpLogs - Success for superadmin: {}, Total log count: {}", 
                    userDetails.getUsername(), logs.size());
            return ResponseEntity.ok(logs);
        } catch (Exception e) {
            log.error("AutoTopUpController.getAllAutoTopUpLogs - Unexpected error for superadmin: {}", userDetails.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Tüm kullanıcıların otomatik yükleme istatistiklerini görüntüleme (SuperAdmin)
     */
    @GetMapping("/admin/stats")
    @PreAuthorize("hasAuthority('SUPERADMIN')")
    public ResponseEntity<AutoTopUpStatsDTO> getAllAutoTopUpStats(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        log.debug("AutoTopUpController.getAllAutoTopUpStats - Method called by superadmin: {}", userDetails.getUsername());
        try {
            AutoTopUpStatsDTO stats = autoTopUpService.getAllAutoTopUpStats();
            log.info("AutoTopUpController.getAllAutoTopUpStats - Success for superadmin: {}", userDetails.getUsername());
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            log.error("AutoTopUpController.getAllAutoTopUpStats - Unexpected error for superadmin: {}", userDetails.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}