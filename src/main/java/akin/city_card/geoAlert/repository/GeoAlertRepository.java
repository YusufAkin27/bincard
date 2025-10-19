package akin.city_card.geoAlert.repository;

import akin.city_card.geoAlert.model.GeoAlert;
import akin.city_card.geoAlert.model.GeoAlertStatus;
import akin.city_card.route.model.Route;
import akin.city_card.station.model.Station;
import akin.city_card.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface GeoAlertRepository extends JpaRepository<GeoAlert, Long> {

    /**
     * Kullanıcının belirli durumdaki uyarılarını getir
     */
    List<GeoAlert> findByUserAndStatus(User user, GeoAlertStatus status);

    /**
     * Kullanıcının tüm uyarılarını tarihe göre sıralı getir
     */
    List<GeoAlert> findByUserOrderByCreatedAtDesc(User user);

    /**
     * Belirli durumdaki tüm uyarıları getir
     */
    List<GeoAlert> findByStatus(GeoAlertStatus status);

    /**
     * Kullanıcının belirli durumdaki uyarı sayısını getir
     */
    int countByUserAndStatus(User user, GeoAlertStatus status);

    /**
     * Kullanıcının belirli rota ve durumdaki uyarı sayısını getir
     */
    int countByUserAndRouteAndStatus(User user, Route route, GeoAlertStatus status);

    /**
     * Kullanıcının belirli rota-durak kombinasyonu için uyarısını getir
     */
    Optional<GeoAlert> findByUserAndRouteAndStationAndStatus(
            User user, Route route, Station station, GeoAlertStatus status);

    /**
     * ID ve kullanıcıya göre uyarı getir
     */
    Optional<GeoAlert> findByIdAndUser(Long id, User user);

    /**
     * Belirli tarihten eski aktif uyarıları getir (temizlik için)
     */
    @Query("SELECT ga FROM GeoAlert ga WHERE ga.status = :status AND ga.createdAt < :cutoffDate")
    List<GeoAlert> findOldAlertsByStatus(@Param("status") GeoAlertStatus status,
                                         @Param("cutoffDate") LocalDateTime cutoffDate);


}