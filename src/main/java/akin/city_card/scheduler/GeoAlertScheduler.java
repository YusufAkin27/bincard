/*package akin.city_card.scheduler;

import akin.city_card.bus.model.Bus;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.service.FCMService;
import akin.city_card.station.model.Station;
import akin.city_card.geoAlert.model.GeoAlert;
import akin.city_card.user.model.User;
import akin.city_card.geoAlert.repository.GeoAlertRepository;
import akin.city_card.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class GeoAlertScheduler {

    private final GeoAlertRepository geoAlertRepository;
    private final UserRepository userRepository;
    private final FCMService fcmService;

    // Örnek olarak 1 dakikada bir kontrol edelim
    @Scheduled(fixedRate = 60_000)
    @Transactional
    public void checkGeoAlerts() {
        List<User> users = userRepository.findAllActiveWithGeoAlerts(); // Özel query olabilir, aktif kullanıcı ve aktif GeoAlert'ler

        for (User user : users) {
            List<GeoAlert> geoAlerts = geoAlertRepository.findAll();
            if (geoAlerts == null || geoAlerts.isEmpty()) continue;

            for (GeoAlert alert : geoAlerts) {
                if (!alert.isActive() || alert.isNotified()) continue;

                // Otobüsleri, rotayı al
                var route = alert.getRoute();
                if (route == null) continue;

                List<Bus> buses = route.getBuses();
                if (buses == null || buses.isEmpty()) continue;

                Station station = alert.getStation();
                if (station == null) continue;

                // Her otobüs için durağa mesafeyi hesapla ve notifyBeforeMinutes ile karşılaştır
                for (Bus bus : buses) {
                    // Otobüsün konumu var mı? (bus.getLatitude(), bus.getLongitude())
                    // Bu örnekte sadece mesafe kontrolü yapılacak (Haversine formülü ile)

                    double distanceMeters = calculateDistance(
                            bus.getCurrentLatitude(), bus.getCurrentLongitude(),
                            station.getLatitude(), station.getLongitude());

                    // Otobüsün varsayılan hızı km/saat, örnek 20 km/h (bunu gerçekte veriden alabilirsin)
                    double busSpeedMetersPerMin = (20_000.0 / 60.0); // 20 km/h = 20,000 m/60 dk

                    // Otobüs durağa ne kadar sürede varır?
                    double etaMinutes = distanceMeters / busSpeedMetersPerMin;

                    if (etaMinutes <= alert.getNotifyBeforeMinutes()) {
                        // Bildirim gönder (bir defaya mahsus)
                        String title = "Yaklaşan Otobüs Uyarısı";
                        String message = String.format(
                                "%s rotasındaki %s durağına %d dakika içinde otobüs var.",
                                route.getName(),
                                station.getName(),
                                (int) Math.ceil(etaMinutes)
                        );

                        fcmService.sendNotificationToToken(user, title, message, NotificationType.INFO, null);

                        alert.setNotified(true);
                        // alert repository ile kaydetmeyi unutma (userRepository ile cascade olabilir)

                        break; // Bir kere bildirim yeter, diğer otobüsleri kontrol etmeye gerek yok
                    }
                }
            }
        }
    }

    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        // Haversine formülü ile metre cinsinden mesafe hesapla
        final int R = 6371000; // Dünya yarıçapı metre cinsinden
        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);
        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2) +
                Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
                        Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }
}


 */