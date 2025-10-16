package akin.city_card.driver.repository;

import akin.city_card.driver.model.DriverPenalty;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

@Repository
public interface DriverPenaltyRepository extends JpaRepository<DriverPenalty, Long> {

    // Sürücüye ait cezalar
    Page<DriverPenalty> findByDriverIdOrderByDateDesc(Long driverId, Pageable pageable);

    List<DriverPenalty> findByDriverIdOrderByDateDesc(Long driverId);

    // Tarih bazlı sorgular
    List<DriverPenalty> findByDateBetweenOrderByDateDesc(LocalDate startDate, LocalDate endDate);

    List<DriverPenalty> findByDriverIdAndDateBetween(Long driverId, LocalDate startDate, LocalDate endDate);

    // Miktar bazlı sorgular
    List<DriverPenalty> findByAmountGreaterThanEqualOrderByAmountDesc(BigDecimal minAmount);

    List<DriverPenalty> findByDriverIdAndAmountGreaterThanEqual(Long driverId, BigDecimal minAmount);

    // İstatistikler
    long countByDriverId(Long driverId);

    @Query("SELECT SUM(p.amount) FROM DriverPenalty p WHERE p.driver.id = :driverId")
    BigDecimal getTotalPenaltyAmountByDriverId(@Param("driverId") Long driverId);

    @Query("SELECT COUNT(p) FROM DriverPenalty p WHERE p.driver.id = :driverId AND p.date BETWEEN :startDate AND :endDate")
    long countByDriverIdAndDateBetween(@Param("driverId") Long driverId,
                                       @Param("startDate") LocalDate startDate,
                                       @Param("endDate") LocalDate endDate);

    // En fazla ceza alan sürücüler
    @Query("SELECT p.driver.id, COUNT(p) as penaltyCount FROM DriverPenalty p " +
            "WHERE p.driver.deleteDate IS NULL " +
            "GROUP BY p.driver.id " +
            "ORDER BY penaltyCount DESC")
    List<Object[]> getDriversWithMostPenalties(Pageable pageable);
}