package akin.city_card.driver.repository;

import akin.city_card.driver.model.Driver;
import akin.city_card.driver.model.Shift;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface DriverRepository extends JpaRepository<Driver, Long>, JpaSpecificationExecutor<Driver> {

    // Temel
    Optional<Driver> findByIdAndDeleteDateIsNull(Long id);

    Page<Driver> findAllByDeleteDateIsNull(Pageable pageable);

    boolean existsByNationalId(String nationalId);

    boolean existsByProfileInfo_Email(String email);

    // Aktiflik
    Page<Driver> findByActiveAndDeleteDateIsNull(Boolean active, Pageable pageable);

    long countByDeleteDateIsNull();

    long countByActiveAndDeleteDateIsNull(Boolean active);

    // Vardiya
    Page<Driver> findByShiftAndActiveAndDeleteDateIsNull(Shift shift, Boolean active, Pageable pageable);

    long countByShiftAndActiveAndDeleteDateIsNull(Shift shift, Boolean active);

    // Lisans & Sağlık
    List<Driver> findByLicenseExpiryDateBeforeAndActiveAndDeleteDateIsNullOrderByLicenseExpiryDate(LocalDate expiryDate, Boolean active);

    long countByLicenseExpiryDateBeforeAndActiveAndDeleteDateIsNull(LocalDate expiryDate, Boolean active);

    List<Driver> findByHealthCertificateExpiryBeforeAndActiveAndDeleteDateIsNullOrderByHealthCertificateExpiry(LocalDate expiryDate, Boolean active);

    long countByHealthCertificateExpiryBeforeAndActiveAndDeleteDateIsNull(LocalDate expiryDate, Boolean active);

    // Performans & Tarih
    Page<Driver> findByActiveAndDeleteDateIsNullAndAverageRatingIsNotNull(Boolean active, Pageable pageable);

    long countByAverageRatingBetweenAndActiveAndDeleteDateIsNull(Double minRating, Double maxRating, Boolean active);

    long countByAverageRatingIsNullAndActiveAndDeleteDateIsNull(Boolean active);

    Page<Driver> findByEmploymentDateBetweenAndDeleteDateIsNull(LocalDate startDate, LocalDate endDate, Pageable pageable);

    long countByCreateDateAfterAndDeleteDateIsNull(LocalDateTime createDate);

    // Arama
    @Query("SELECT d FROM Driver d WHERE d.deleteDate IS NULL AND " +
            "(LOWER(d.profileInfo.name) LIKE %:query% OR " +
            "LOWER(d.profileInfo.surname) LIKE %:query% OR " +
            "LOWER(d.nationalId) LIKE %:query% OR " +
            "LOWER(CONCAT(d.profileInfo.name, ' ', d.profileInfo.surname)) LIKE %:query%)")
    Page<Driver> findBySearchQuery(@Param("query") String query, Pageable pageable);

    // Cezalı sürücüler
    @Query("SELECT DISTINCT d FROM Driver d JOIN d.penalties p WHERE d.deleteDate IS NULL ORDER BY d.profileInfo.name")
    Page<Driver> findDriversWithPenalties(Pageable pageable);

    @Query("SELECT COUNT(DISTINCT d.id) FROM Driver d JOIN d.penalties p WHERE d.deleteDate IS NULL")
    long countDriversWithPenalties();

    @Query(value = "SELECT AVG(DATEDIFF(CURRENT_DATE, employment_date) / 365.0) " +
            "FROM driver " +
            "WHERE delete_date IS NULL AND employment_date IS NOT NULL",
            nativeQuery = true)
    Double getAverageExperienceYears();

    @Query("SELECT MAX(d.averageRating) FROM Driver d WHERE d.deleteDate IS NULL AND d.averageRating IS NOT NULL")
    Double getHighestAverageRating();

    @Query("SELECT MIN(d.averageRating) FROM Driver d WHERE d.deleteDate IS NULL AND d.averageRating IS NOT NULL AND d.averageRating > 0")
    Double getLowestAverageRating();

    Driver findByUserNumber(String telephone);

    Optional<Driver> findByCardUid(String cardUid);
}
