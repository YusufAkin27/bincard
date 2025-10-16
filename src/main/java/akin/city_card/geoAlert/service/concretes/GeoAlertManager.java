package akin.city_card.geoAlert.service.concretes;

import akin.city_card.bus.exceptions.RouteNotFoundException;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusStatus;
import akin.city_card.bus.repository.BusRepository;
import akin.city_card.geoAlert.core.request.GeoAlertRequest;
import akin.city_card.geoAlert.core.response.GeoAlertDTO;
import akin.city_card.geoAlert.model.GeoAlert;
import akin.city_card.geoAlert.model.GeoAlertStatus;
import akin.city_card.geoAlert.repository.GeoAlertRepository;
import akin.city_card.geoAlert.service.abstracts.GeoAlertService;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.service.FCMService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.exceptions.RouteNotFoundStationException;
import akin.city_card.route.model.Route;
import akin.city_card.route.model.RouteDirection;
import akin.city_card.route.repository.RouteRepository;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.station.exceptions.StationNotFoundException;
import akin.city_card.station.model.Station;
import akin.city_card.station.repository.StationRepository;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class GeoAlertManager implements GeoAlertService {

    private final UserRepository userRepository;
    private final RouteRepository routeRepository;
    private final StationRepository stationRepository;
    private final GeoAlertRepository geoAlertRepository;
    private final BusRepository busRepository;
    private final FCMService fcmService;

    private static final double EARTH_RADIUS_KM = 6371.0;
    private static final int MAX_ALERTS_PER_USER = 10;
    private static final double DEFAULT_ALERT_RADIUS_METERS = 500.0;

    @Override
    @Transactional(readOnly = true)
    public List<GeoAlertDTO> getActiveGeoAlerts(String username) throws UserNotFoundException {
        User user = findUserByUsername(username);
        List<GeoAlert> activeAlerts = geoAlertRepository.findByUserAndStatus(user, GeoAlertStatus.ACTIVE);
        return activeAlerts.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Override
    public long countGeoAlertsByStatus(String username, GeoAlertStatus status) {

        return 0;
    }

    @Override
    public ResponseMessage deleteGeoAlertAsAdmin(Long alertId, String username) {
        return null;
    }

    @Override
    public List<GeoAlertDTO> getGeoAlertsByUsername(UserDetails userDetails, String username, GeoAlertStatus status) {
        return List.of();
    }

    @Override
    public List<GeoAlertDTO> getAllGeoAlerts(String username, GeoAlertStatus status) {
        return List.of();
    }

    @Override
    @Transactional(readOnly = true)
    public List<GeoAlertDTO> getGeoAlertHistory(String username) throws UserNotFoundException {
        User user = findUserByUsername(username);
        List<GeoAlert> allAlerts = geoAlertRepository.findByUserOrderByCreatedAtDesc(user);
        return allAlerts.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Override
    public ResponseMessage createGeoAlert(String username, GeoAlertRequest alertRequest)
            throws UserNotFoundException, RouteNotFoundException, StationNotFoundException, RouteNotFoundStationException {

        User user = findUserByUsername(username);

        // Kullanıcının aktif uyarı sayısını kontrol et
        int activeAlertCount = geoAlertRepository.countByUserAndStatus(user, GeoAlertStatus.ACTIVE);
        if (activeAlertCount >= MAX_ALERTS_PER_USER) {
            return new ResponseMessage("Maksimum " + MAX_ALERTS_PER_USER + " aktif uyarınız olabilir.", false);
        }

        Route route = routeRepository.findById(alertRequest.getRouteId())
                .orElseThrow(RouteNotFoundException::new);

        Station station = stationRepository.findById(alertRequest.getStationId())
                .orElseThrow(StationNotFoundException::new);

        // Durakın rotada olup olmadığını kontrol et
        if (!isStationInRoute(route, station)) {
            throw new RouteNotFoundStationException();
        }

        // Aynı rota-durak kombinasyonu için aktif uyarı var mı kontrol et
        Optional<GeoAlert> existingAlert = geoAlertRepository
                .findByUserAndRouteAndStationAndStatus(user, route, station, GeoAlertStatus.ACTIVE);

        if (existingAlert.isPresent()) {
            return new ResponseMessage("Bu rota ve durak için zaten aktif bir uyarınız bulunmaktadır.", false);
        }

        // Kullanıcının bildirim tercihlerinden bildirim süresini al
        int notifyBeforeMinutes = alertRequest.getNotifyBeforeMinutes();
        if (user.getNotificationPreferences() != null &&
                user.getNotificationPreferences().getNotifyBeforeMinutes() != null) {
            notifyBeforeMinutes = user.getNotificationPreferences().getNotifyBeforeMinutes();
        }


        GeoAlert geoAlert = GeoAlert.builder()
                .user(user)
                .route(route)
                .station(station)
                .alertName(alertRequest.getAlertName())
                .notifyBeforeMinutes(notifyBeforeMinutes)
                .radiusMeters((alertRequest.getRadiusMeters() != null) ?
                        alertRequest.getRadiusMeters() : DEFAULT_ALERT_RADIUS_METERS)
                .status(GeoAlertStatus.ACTIVE)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        geoAlertRepository.save(geoAlert);

        log.info("Kullanıcı {} için yeni geo uyarısı oluşturuldu: {} (Rota: {}, Durak: {})",
                username, geoAlert.getAlertName(), route.getName(), station.getName());

        return new ResponseMessage("Araç konum uyarısı başarıyla oluşturuldu.", true);
    }

    @Override
    public ResponseMessage cancelGeoAlert(String username, Long alertId) throws UserNotFoundException {
        User user = findUserByUsername(username);

        Optional<GeoAlert> alertOpt = geoAlertRepository.findByIdAndUser(alertId, user);
        if (alertOpt.isEmpty()) {
            return new ResponseMessage("Uyarı bulunamadı.", false);
        }

        GeoAlert alert = alertOpt.get();
        if (alert.getStatus() != GeoAlertStatus.ACTIVE) {
            return new ResponseMessage("Bu uyarı zaten aktif değil.", false);
        }

        alert.setStatus(GeoAlertStatus.CANCELLED);
        alert.setUpdatedAt(LocalDateTime.now());
        alert.setCancelledAt(LocalDateTime.now());

        geoAlertRepository.save(alert);

        log.info("Kullanıcı {} tarafından {} ID'li geo uyarısı iptal edildi", username, alertId);

        return new ResponseMessage("Uyarı başarıyla iptal edildi.", true);
    }

    @Override
    public List<GeoAlertDTO> getGeoAlerts(String username) throws UserNotFoundException {
        return getActiveGeoAlerts(username);
    }

    @Override
    public ResponseMessage addGeoAlert(String username, GeoAlertRequest alertRequest)
            throws UserNotFoundException, RouteNotFoundException, StationNotFoundException, RouteNotFoundStationException {
        return createGeoAlert(username, alertRequest);
    }

    @Override
    public ResponseMessage deleteGeoAlert(String username, Long alertId) throws UserNotFoundException {
        User user = findUserByUsername(username);

        Optional<GeoAlert> alertOpt = geoAlertRepository.findByIdAndUser(alertId, user);
        if (alertOpt.isEmpty()) {
            return new ResponseMessage("Uyarı bulunamadı.", false);
        }

        geoAlertRepository.delete(alertOpt.get());

        log.info("Kullanıcı {} tarafından {} ID'li geo uyarısı kalıcı olarak silindi", username, alertId);

        return new ResponseMessage("Uyarı başarıyla silindi.", true);
    }

    @Override
    public ResponseMessage reactivateGeoAlert(String username, Long alertId) throws UserNotFoundException {
        User user = findUserByUsername(username);

        Optional<GeoAlert> alertOpt = geoAlertRepository.findByIdAndUser(alertId, user);
        if (alertOpt.isEmpty()) {
            return new ResponseMessage("Uyarı bulunamadı.", false);
        }

        GeoAlert alert = alertOpt.get();
        if (alert.getStatus() == GeoAlertStatus.ACTIVE) {
            return new ResponseMessage("Bu uyarı zaten aktif.", false);
        }

        if (alert.getStatus() == GeoAlertStatus.COMPLETED) {
            return new ResponseMessage("Tamamlanmış uyarılar yeniden aktifleştirilemez.", false);
        }

        // Aktif uyarı sayısını kontrol et
        int activeAlertCount = geoAlertRepository.countByUserAndStatus(user, GeoAlertStatus.ACTIVE);
        if (activeAlertCount >= MAX_ALERTS_PER_USER) {
            return new ResponseMessage("Maksimum " + MAX_ALERTS_PER_USER + " aktif uyarınız olabilir.", false);
        }

        alert.setStatus(GeoAlertStatus.ACTIVE);
        alert.setUpdatedAt(LocalDateTime.now());
        alert.setCancelledAt(null);

        geoAlertRepository.save(alert);

        log.info("Kullanıcı {} tarafından {} ID'li geo uyarısı yeniden aktifleştirildi", username, alertId);

        return new ResponseMessage("Uyarı başarıyla yeniden aktifleştirildi.", true);
    }

    @Override
    @Transactional(readOnly = true)
    public int getActiveAlertCount(String username, Long routeId) throws UserNotFoundException {
        User user = findUserByUsername(username);

        if (routeId != null) {
            Route route = routeRepository.findById(routeId).orElse(null);
            if (route == null) {
                return 0;
            }
            return geoAlertRepository.countByUserAndRouteAndStatus(user, route, GeoAlertStatus.ACTIVE);
        }

        return geoAlertRepository.countByUserAndStatus(user, GeoAlertStatus.ACTIVE);
    }

    /**
     * Her 15 saniyede bir çalışan zamanlayıcı
     * Aktif uyarıları kontrol eder ve gerekirse bildirim gönderir
     */
    @Scheduled(fixedRate = 15000) // 15 saniye
    @Async
    public void processActiveAlerts() {
        try {
            List<GeoAlert> activeAlerts = geoAlertRepository.findByStatus(GeoAlertStatus.ACTIVE);

            log.debug("Kontrol edilecek aktif uyarı sayısı: {}", activeAlerts.size());

            for (GeoAlert alert : activeAlerts) {
                processIndividualAlert(alert);
            }
        } catch (Exception e) {
            log.error("Geo uyarıları işlenirken hata oluştu", e);
        }
    }

    /**
     * Eski aktif uyarıları temizleme (günde bir kez çalışır)
     * 24 saatten eski aktif uyarıları otomatik olarak iptal eder
     */
    @Scheduled(fixedRate = 86400000) // 24 saat
    @Async
    public void cleanupOldAlerts() {
        try {
            LocalDateTime cutoffTime = LocalDateTime.now().minusHours(24);
            List<GeoAlert> oldAlerts = geoAlertRepository.findOldAlertsByStatus(GeoAlertStatus.ACTIVE, cutoffTime);

            for (GeoAlert alert : oldAlerts) {
                alert.setStatus(GeoAlertStatus.EXPIRED);
                alert.setUpdatedAt(LocalDateTime.now());
                geoAlertRepository.save(alert);
            }

            if (!oldAlerts.isEmpty()) {
                log.info("{} adet eski geo uyarısı otomatik olarak süresi dolmuş olarak işaretlendi", oldAlerts.size());
            }
        } catch (Exception e) {
            log.error("Eski geo uyarıları temizlenirken hata oluştu", e);
        }
    }

    private void processIndividualAlert(GeoAlert alert) {
        try {
            // Bu rotadaki aktif araçları getir
            List<Bus> activeBuses = busRepository.findByAssignedRouteAndIsActiveAndStatus(
                    alert.getRoute(), true, BusStatus.CALISIYOR);

            for (Bus bus : activeBuses) {
                if (shouldTriggerAlert(alert, bus)) {
                    triggerAlert(alert, bus);
                    return; // Uyarı tetiklendi, döngüden çık
                }
            }
        } catch (Exception e) {
            log.error("Uyarı {} işlenirken hata oluştu", alert.getId(), e);
        }
    }

    private boolean shouldTriggerAlert(GeoAlert alert, Bus bus) {
        // Araç konumu bilgisi var mı?
        if (bus.getCurrentLatitude() == null || bus.getCurrentLongitude() == null) {
            return false;
        }

        Station targetStation = alert.getStation();

        // Araç hedef durağa yaklaşıyor mu kontrol et
        double distanceToStation = calculateDistance(
                bus.getCurrentLatitude(), bus.getCurrentLongitude(),
                targetStation.getLocation().getLatitude(), targetStation.getLocation().getLongitude()
        );

        // Araç belirlenen yarıçap içinde mi?
        double alertRadiusKm = alert.getRadiusMeters() / 1000.0;
        if (distanceToStation > alertRadiusKm) {
            return false;
        }

        // Araç hedef durağa doğru hareket ediyor mu?
        if (!isMovingTowardsStation(bus, targetStation, alert.getRoute())) {
            return false;
        }

        // Zamanlama kontrolü - belirlenen dakika öncesinde mi?
        return isTimeToNotify(alert, bus, targetStation);
    }

    private boolean isTimeToNotify(GeoAlert alert, Bus bus, Station targetStation) {
        try {
            // Aracın hızını ve durağa mesafesini kullanarak varış süresini tahmin et
            double distanceKm = calculateDistance(
                    bus.getCurrentLatitude(), bus.getCurrentLongitude(),
                    targetStation.getLocation().getLatitude(), targetStation.getLocation().getLongitude()
            );

            // Ortalama şehir içi otobüs hızı 20 km/h olarak varsayılır
            double averageSpeedKmh = 20.0;
            double estimatedMinutesToArrival = (distanceKm / averageSpeedKmh) * 60;

            // Kullanıcının belirlediği süre öncesinde bildirim gönder
            return estimatedMinutesToArrival <= alert.getNotifyBeforeMinutes();

        } catch (Exception e) {
            log.error("Bildirim zamanı hesaplanırken hata oluştu", e);
            return false;
        }
    }

    private boolean isMovingTowardsStation(Bus bus, Station targetStation, Route route) {
        // Aracın hangi yönde gittiğini kontrol et
        RouteDirection currentDirection = bus.getCurrentDirection();
        if (currentDirection == null) {
            return false;
        }

        // Hedef durak bu yönde var mı kontrol et
        return currentDirection.getStationNodes().stream()
                .anyMatch(node -> node.getFromStation().equals(targetStation) ||
                        node.getToStation().equals(targetStation));
    }

    private void triggerAlert(GeoAlert alert, Bus bus) {
        try {
            // Performans metriği hesapla
            LocalDateTime now = LocalDateTime.now();
            long actualMinutes = ChronoUnit.MINUTES.between(alert.getCreatedAt(), now);

            // Uyarı durumunu güncelle
            alert.setStatus(GeoAlertStatus.COMPLETED);
            alert.setNotifiedAt(now);
            alert.setUpdatedAt(now);
            alert.setTriggeredByBusPlate(bus.getNumberPlate());
            alert.setActualNotificationMinutes((int) actualMinutes);
            geoAlertRepository.save(alert);

            // Bildirim mesajını oluştur
            String title = "Araç Yaklaşıyor!";
            String message = String.format(
                    "%s rotasındaki %s plakalı araç %s durağına yaklaşıyor!",
                    alert.getRoute().getName(),
                    bus.getNumberPlate(),
                    alert.getStation().getName()
            );

            // Kullanıcının bildirim tercihlerini kontrol et ve bildirim gönder
            sendNotificationBasedOnPreferences(alert.getUser(), title, message);

            log.info("Geo uyarısı tetiklendi: {} - Kullanıcı: {}, Rota: {}, Durak: {}, Araç: {}",
                    alert.getAlertName(), alert.getUser().getUsername(),
                    alert.getRoute().getName(), alert.getStation().getName(), bus.getNumberPlate());

        } catch (Exception e) {
            log.error("Uyarı {} tetiklenirken hata oluştu", alert.getId(), e);
        }
    }

    private void sendNotificationBasedOnPreferences(User user, String title, String message) {
        if (user.getNotificationPreferences() == null) {
            // Varsayılan olarak push notification gönder
            sendPushNotification(user, title, message);
            return;
        }

        // Push notification kontrolü
        if (user.getNotificationPreferences().isPushEnabled() &&
                user.getNotificationPreferences().isFcmActive()) {
            sendPushNotification(user, title, message);
        }

        // SMS kontrolü
        if (user.getNotificationPreferences().isSmsEnabled()) {
            sendSmsNotification(user, message);
        }

        // Email kontrolü
        if (user.getNotificationPreferences().isEmailEnabled()) {
            sendEmailNotification(user, title, message);
        }
    }

    private void sendPushNotification(User user, String title, String message) {
        try {
            fcmService.sendNotificationToToken(user, title, message, NotificationType.GEO_ALERT, null);
            log.debug("Push notification gönderildi: {}", user.getUsername());
        } catch (Exception e) {
            log.error("Push notification gönderilemedi: {}", user.getUsername(), e);
        }
    }

    private void sendSmsNotification(User user, String message) {
        try {
            // SMS servis entegrasyonu burada yapılacak
            // Örnek: smsService.sendSms(user.getPhoneNumber(), message);
            log.debug("SMS bildirimi gönderildi: {}", user.getUsername());
        } catch (Exception e) {
            log.error("SMS bildirimi gönderilemedi: {}", user.getUsername(), e);
        }
    }

    private void sendEmailNotification(User user, String title, String message) {
        try {
            // Email servis entegrasyonu burada yapılacak
            // Örnek: emailService.sendEmail(user.getEmail(), title, message);
            log.debug("Email bildirimi gönderildi: {}", user.getUsername());
        } catch (Exception e) {
            log.error("Email bildirimi gönderilemedi: {}", user.getUsername(), e);
        }
    }

    private boolean isStationInRoute(Route route, Station station) {
        return route.getDirections().stream()
                .flatMap(direction -> direction.getStationNodes().stream())
                .anyMatch(node -> node.getFromStation().equals(station) ||
                        node.getToStation().equals(station));
    }

    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        double lat1Rad = Math.toRadians(lat1);
        double lon1Rad = Math.toRadians(lon1);
        double lat2Rad = Math.toRadians(lat2);
        double lon2Rad = Math.toRadians(lon2);

        double deltaLat = lat2Rad - lat1Rad;
        double deltaLon = lon2Rad - lon1Rad;

        double a = Math.sin(deltaLat / 2) * Math.sin(deltaLat / 2) +
                Math.cos(lat1Rad) * Math.cos(lat2Rad) *
                        Math.sin(deltaLon / 2) * Math.sin(deltaLon / 2);

        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

        return EARTH_RADIUS_KM * c;
    }

    private User findUserByUsername(String username) throws UserNotFoundException {
        return userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);
    }

    private GeoAlertDTO convertToDTO(GeoAlert alert) {
        return GeoAlertDTO.builder()
                .id(alert.getId())
                .alertName(alert.getAlertName())
                .routeName(alert.getRoute().getName())
                .routeCode(alert.getRoute().getCode())
                .stationName(alert.getStation().getName())
                .notifyBeforeMinutes(alert.getNotifyBeforeMinutes())
                .radiusMeters(alert.getRadiusMeters())
                .status(alert.getStatus())
                .createdAt(alert.getCreatedAt())
                .notifiedAt(alert.getNotifiedAt())
                .cancelledAt(alert.getCancelledAt())
                .build();
    }
}