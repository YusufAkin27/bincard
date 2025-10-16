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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;

@RestController
@RequestMapping("/v1/api/auto_top_up")
@RequiredArgsConstructor
public class AutoTopUpController {

    private final AutoTopUpService autoTopUpService;

    /**
     * Kullanıcının otomatik yükleme konfigürasyonlarını listeleme
     */
    @GetMapping()
    public ResponseEntity<List<AutoTopUpConfigDTO>> getAutoTopUpConfigs(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        try {
            List<AutoTopUpConfigDTO> configs = autoTopUpService.getAutoTopUpConfigs(userDetails.getUsername());
            return ResponseEntity.ok(configs);
        } catch (UserNotFoundException e) {
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
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
        try {
            ResponseMessage result = autoTopUpService.addAutoTopUpConfig(userDetails.getUsername(), configRequest);
            return ResponseEntity.status(result.isSuccess() ? HttpStatus.CREATED : HttpStatus.BAD_REQUEST).body(result);
        } catch (UserNotFoundException e) {
            return ResponseEntity.notFound().build();
        } catch (BusCardNotFoundException e) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Belirtilen kart bulunamadı.", false));
        } catch (WalletIsEmptyException e) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Cüzdan bulunamadı.", false));
        } catch (Exception e) {
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
        try {
            ResponseMessage result = autoTopUpService.updateAutoTopUpConfig(userDetails.getUsername(), configId, configRequest);
            return ResponseEntity.ok(result);
        } catch (UserNotFoundException e) {
            return ResponseEntity.notFound().build();
        } catch (AutoTopUpConfigNotFoundException e) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Belirtilen konfigürasyon bulunamadı.", false));
        } catch (BusCardNotFoundException e) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Belirtilen kart bulunamadı.", false));
        } catch (Exception e) {
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
        try {
            ResponseMessage result = autoTopUpService.deleteAutoTopUpConfig(userDetails.getUsername(), configId);
            return ResponseEntity.ok(result);
        } catch (UserNotFoundException e) {
            return ResponseEntity.notFound().build();
        } catch (AutoTopUpConfigNotFoundException e) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Belirtilen konfigürasyon bulunamadı.", false));
        } catch (Exception e) {
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
        try {
            ResponseMessage result = autoTopUpService.toggleAutoTopUpConfig(userDetails.getUsername(), configId);
            return ResponseEntity.ok(result);
        } catch (UserNotFoundException e) {
            return ResponseEntity.notFound().build();
        } catch (AutoTopUpConfigNotFoundException e) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Belirtilen konfigürasyon bulunamadı.", false));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Konfigürasyon durumu değiştirilemedi: " + e.getMessage(), false));
        }
    }

    /**
     * Manuel otomatik yükleme tetikleme (belirli bir kart için)
     */
    @PostMapping("/process/{busCardId}")
    public ResponseEntity<ResponseMessage> processAutoTopUp(
            @PathVariable Long busCardId,
            @RequestParam(required = false) BigDecimal currentBalance
    ) {
        try {
            // Eğer currentBalance verilmemişse, kartın mevcut bakiyesini kullan
            ResponseMessage result = autoTopUpService.processAutoTopUp(busCardId, currentBalance);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
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
        try {
            ResponseMessage result = autoTopUpService.processAutoTopUpForUser(userDetails.getUsername());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
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
        try {
            List<AutoTopUpLogDTO> logs = autoTopUpService.getAutoTopUpLogs(userDetails.getUsername());
            return ResponseEntity.ok(logs);
        } catch (Exception e) {
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
        try {
            List<AutoTopUpLogDTO> logs = autoTopUpService.getAutoTopUpLogsByConfig(userDetails.getUsername(), configId);
            return ResponseEntity.ok(logs);
        } catch (Exception e) {
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
        try {
            AutoTopUpStatsDTO stats = autoTopUpService.getAutoTopUpStats(userDetails.getUsername());
            return ResponseEntity.ok(stats);
        } catch (UserNotFoundException e) {
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Belirli bir kartın otomatik yükleme durumunu kontrol etme
     */
    @GetMapping("/check/{busCardId}")
    public ResponseEntity<ResponseMessage> checkAutoTopUpStatus(
            @PathVariable Long busCardId,
            @RequestParam(required = false) BigDecimal currentBalance
    ) {
        try {
            boolean hasActiveConfig = autoTopUpService.hasActiveAutoTopUpForCard(busCardId);

            if (!hasActiveConfig) {
                return ResponseEntity.ok(new ResponseMessage("Bu kart için aktif otomatik yükleme konfigürasyonu bulunmuyor.", false));
            }

            if (currentBalance != null) {
                boolean canProcess = autoTopUpService.canProcessAutoTopUp(busCardId, currentBalance);
                String message = canProcess
                        ? "Otomatik yükleme işlemi gerçekleştirilebilir."
                        : "Otomatik yükleme için koşullar sağlanmıyor (eşik değeri veya cüzdan bakiyesi).";
                return ResponseEntity.ok(new ResponseMessage(message, canProcess));
            }

            return ResponseEntity.ok(new ResponseMessage("Bu kart için aktif otomatik yükleme konfigürasyonu bulunuyor.", true));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Kontrol işlemi başarısız: " + e.getMessage(), false));
        }
    }
}