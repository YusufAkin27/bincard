package akin.city_card.geoAlert.controller;

import akin.city_card.bus.exceptions.RouteNotFoundException;
import akin.city_card.geoAlert.core.request.GeoAlertRequest;
import akin.city_card.geoAlert.core.response.GeoAlertDTO;
import akin.city_card.geoAlert.model.GeoAlertStatus;
import akin.city_card.geoAlert.service.abstracts.GeoAlertService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.exceptions.RouteNotFoundStationException;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.station.exceptions.StationNotFoundException;
import akin.city_card.user.core.response.Views;
import com.fasterxml.jackson.annotation.JsonView;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/geo-alert")
@RequiredArgsConstructor
@Slf4j
public class GeoAlertController {

    private final GeoAlertService geoAlertService;

    /**
     * Kullanıcının aktif geo uyarılarını getir
     */
    @GetMapping("/alerts")
    @JsonView(Views.User.class)
    public ResponseEntity<List<GeoAlertDTO>> getActiveGeoAlerts(
            @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {

        log.info("Kullanıcı {} için aktif geo uyarıları getiriliyor", userDetails.getUsername());
        List<GeoAlertDTO> alerts = geoAlertService.getActiveGeoAlerts(userDetails.getUsername());
        return ResponseEntity.ok(alerts);
    }

    /**
     * Kullanıcının tüm geo uyarı geçmişini getir (aktif + tamamlanmış)
     */
    @GetMapping("/alerts/history")
    @JsonView(Views.User.class)
    public ResponseEntity<List<GeoAlertDTO>> getGeoAlertHistory(
            @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {

        log.info("Kullanıcı {} için geo uyarı geçmişi getiriliyor", userDetails.getUsername());
        List<GeoAlertDTO> alerts = geoAlertService.getGeoAlertHistory(userDetails.getUsername());
        return ResponseEntity.ok(alerts);
    }

    /**
     * Yeni geo uyarısı oluştur
     */
    @PostMapping("/alerts")
    public ResponseEntity<ResponseMessage> createGeoAlert(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody GeoAlertRequest alertRequest)
            throws UserNotFoundException, StationNotFoundException, RouteNotFoundException, RouteNotFoundStationException {

        log.info("Kullanıcı {} için yeni geo uyarısı oluşturuluyor: rota={}, durak={}",
                userDetails.getUsername(), alertRequest.getRouteId(), alertRequest.getStationId());

        ResponseMessage response = geoAlertService.createGeoAlert(userDetails.getUsername(), alertRequest);
        return ResponseEntity.ok(response);
    }

    /**
     * Geo uyarısını manuel olarak iptal et
     */
    @PatchMapping("/alerts/{alertId}/cancel")
    public ResponseEntity<ResponseMessage> cancelGeoAlert(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long alertId) throws UserNotFoundException {

        log.info("Kullanıcı {} tarafından {} ID'li geo uyarısı iptal ediliyor",
                userDetails.getUsername(), alertId);

        ResponseMessage response = geoAlertService.cancelGeoAlert(userDetails.getUsername(), alertId);
        return ResponseEntity.ok(response);
    }

    /**
     * Geo uyarısını kalıcı olarak sil (kullanıcı tarafından)
     */
    @DeleteMapping("/alerts/{alertId}")
    public ResponseEntity<ResponseMessage> deleteGeoAlert(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long alertId) throws UserNotFoundException {

        log.info("Kullanıcı {} tarafından {} ID'li geo uyarısı siliniyor",
                userDetails.getUsername(), alertId);

        ResponseMessage response = geoAlertService.deleteGeoAlert(userDetails.getUsername(), alertId);
        return ResponseEntity.ok(response);
    }

    /**
     * Geo uyarısını yeniden aktifleştir
     */
    @PatchMapping("/alerts/{alertId}/reactivate")
    public ResponseEntity<ResponseMessage> reactivateGeoAlert(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long alertId) throws UserNotFoundException {

        log.info("Kullanıcı {} tarafından {} ID'li geo uyarısı yeniden aktifleştiriliyor",
                userDetails.getUsername(), alertId);

        ResponseMessage response = geoAlertService.reactivateGeoAlert(userDetails.getUsername(), alertId);
        return ResponseEntity.ok(response);
    }


    /**
     * Tüm kullanıcıların uyarılarını getir (isteğe bağlı statü filtresiyle)
     */
    @GetMapping("/admin/alerts")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('GEO_ALERT_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<List<GeoAlertDTO>> getAllGeoAlerts(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(required = false) GeoAlertStatus status) {

        log.info("Admin tarafından tüm uyarılar isteniyor. Filtre: status={}", status);
        List<GeoAlertDTO> alerts = geoAlertService.getAllGeoAlerts(userDetails.getUsername(), status);
        return ResponseEntity.ok(alerts);
    }

    /**
     * Belirli bir kullanıcının uyarılarını getir
     */
    @GetMapping("/admin/alerts/user/{username}")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('GEO_ALERT_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<List<GeoAlertDTO>> getGeoAlertsByUser(
            @PathVariable String username,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(required = false) GeoAlertStatus status) {

        log.info("Admin tarafından {} kullanıcısının uyarıları isteniyor. Statü: {}", username, status);
        List<GeoAlertDTO> alerts = geoAlertService.getGeoAlertsByUsername(userDetails, username, status);
        return ResponseEntity.ok(alerts);
    }

    /**
     * Belirli bir uyarıyı admin olarak sil
     */
    @DeleteMapping("/admin/alerts/{alertId}")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('GEO_ALERT_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> deleteAlertById(
            @PathVariable Long alertId,
            @AuthenticationPrincipal UserDetails userDetails) {

        log.warn("Admin tarafından {} ID'li uyarı siliniyor", alertId);
        ResponseMessage response = geoAlertService.deleteGeoAlertAsAdmin(alertId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    /**
     * Belirli bir statüye sahip kaç uyarı olduğunu getir (admin)
     */
    @GetMapping("/admin/alerts/count")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('GEO_ALERT_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<Long> countGeoAlertsByStatus(
            @RequestParam(required = false) GeoAlertStatus status,
            @AuthenticationPrincipal UserDetails userDetails) {

        long count = geoAlertService.countGeoAlertsByStatus(userDetails.getUsername(), status);
        return ResponseEntity.ok(count);
    }
}
