package akin.city_card.paymentPoint.repository;

import akin.city_card.paymentPoint.model.PaymentMethod;
import akin.city_card.paymentPoint.model.PaymentPoint;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface PaymentPointRepository extends JpaRepository<PaymentPoint, Long> {
    // Şehir bazlı arama
    Page<PaymentPoint> findByAddress_CityContainingIgnoreCase(String city, Pageable pageable);

    // Aktif/pasif durumuna göre filtreleme
    Page<PaymentPoint> findByActive(boolean active, Pageable pageable);

    List<PaymentPoint> findByActive(boolean active);

    // İsme göre arama
    Page<PaymentPoint> findByNameContainingIgnoreCase(String name, Pageable pageable);

    // Ödeme yöntemi bazlı arama
    @Query("SELECT p FROM PaymentPoint p JOIN p.paymentMethods pm WHERE pm = :paymentMethod")
    Page<PaymentPoint> findByPaymentMethodsContaining(@Param("paymentMethod") PaymentMethod paymentMethod, Pageable pageable);

    @Query(value = """
            SELECT * FROM (
                SELECT p.*, 
                (6371 * acos(cos(radians(:latitude)) * cos(radians(p.latitude)) * 
                             cos(radians(p.longitude) - radians(:longitude)) + 
                             sin(radians(:latitude)) * sin(radians(p.latitude)))) AS distance
                FROM payment_points p 
                WHERE p.active = true
            ) sub
            WHERE sub.distance <= :radiusKm
            ORDER BY sub.distance
            LIMIT :#{#pageable.pageSize} OFFSET :#{#pageable.offset}
            """,
            countQuery = """
                        SELECT COUNT(*) FROM (
                            SELECT p.id,
                            (6371 * acos(cos(radians(:latitude)) * cos(radians(p.latitude)) * 
                                         cos(radians(p.longitude) - radians(:longitude)) + 
                                         sin(radians(:latitude)) * sin(radians(p.latitude)))) AS distance
                            FROM payment_points p 
                            WHERE p.active = true
                        ) sub
                        WHERE sub.distance <= :radiusKm
                    """,
            nativeQuery = true)
    Page<PaymentPoint> findNearbyPaymentPoints(
            @Param("latitude") double latitude,
            @Param("longitude") double longitude,
            @Param("radiusKm") double radiusKm,
            Pageable pageable
    );

    @Query("""
                SELECT DISTINCT p FROM PaymentPoint p
                LEFT JOIN p.paymentMethods pm
                WHERE 
                  (:latitude IS NULL OR :longitude IS NULL OR :radiusKm IS NULL OR
                   (6371 * acos(cos(radians(:latitude)) * cos(radians(p.location.latitude)) *
                               cos(radians(p.location.longitude) - radians(:longitude)) +
                               sin(radians(:latitude)) * sin(radians(p.location.latitude)))) <= :radiusKm)
                  AND (:name IS NULL OR LOWER(p.name) LIKE LOWER(CONCAT('%', :name, '%')))
                  AND (:city IS NULL OR LOWER(p.address.city) LIKE LOWER(CONCAT('%', :city, '%')))
                  AND (:district IS NULL OR LOWER(p.address.district) LIKE LOWER(CONCAT('%', :district, '%')))
                  AND (:active IS NULL OR p.active = :active)
                  AND (:paymentMethods IS NULL OR pm IN :paymentMethods)
                ORDER BY p.name
            """)
    Page<PaymentPoint> searchPaymentPoints(
            @Param("latitude") Double latitude,
            @Param("longitude") Double longitude,
            @Param("radiusKm") Double radiusKm,
            @Param("name") String name,
            @Param("city") String city,
            @Param("district") String district,
            @Param("paymentMethods") List<PaymentMethod> paymentMethods,
            @Param("active") Boolean active,
            Pageable pageable
    );


    // İlçe bazlı arama
    Page<PaymentPoint> findByAddress_DistrictContainingIgnoreCase(String district, Pageable pageable);

    // Çalışma saatlerine göre arama
    Page<PaymentPoint> findByWorkingHoursContainingIgnoreCase(String workingHours, Pageable pageable);

    // Aktif ödeme noktalarını getir
    Page<PaymentPoint> findByActiveTrue(Pageable pageable);

    // Pasif ödeme noktalarını getir
    Page<PaymentPoint> findByActiveFalse(Pageable pageable);

    // Belirli bir şehir ve ilçedeki ödeme noktaları
    Page<PaymentPoint> findByAddress_CityAndAddress_District(String city, String district, Pageable pageable);

}
