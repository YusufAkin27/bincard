package akin.city_card.bus.repository;

import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusStatus;
import akin.city_card.route.model.Route;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface BusRepository extends JpaRepository<Bus, Long> {


    Optional<Bus> findByIdAndIsDeletedFalse(Long id);

    Optional<Bus> findByValidatorId(String validatorId);

    Page<Bus> findAllByIsActiveTrueAndIsDeletedFalse(Pageable pageable);


    boolean existsByNumberPlateAndIsDeletedFalse(String numberPlate);

    @Query("SELECT b FROM Bus b WHERE UPPER(b.numberPlate) LIKE UPPER(CONCAT('%', :numberPlate, '%')) AND b.isDeleted = false")
    Page<Bus> findByNumberPlateContainingIgnoreCaseAndIsDeletedFalse(@Param("numberPlate") String numberPlate, Pageable pageable);


    @Query("SELECT CASE WHEN COUNT(b) > 0 THEN true ELSE false END FROM Bus b WHERE b.driver.id = :driverId AND b.isActive = true AND b.isDeleted = false")
    boolean existsByDriverIdAndIsActiveTrueAndIsDeletedFalse(@Param("driverId") Long driverId);

    @Query("SELECT b FROM Bus b WHERE b.driver.id = :driverId AND b.isActive = true AND b.isDeleted = false")
    Optional<Bus> findByDriverIdAndIsActiveTrueAndIsDeletedFalse(@Param("driverId") Long driverId);

    @Query("SELECT b FROM Bus b WHERE b.driver.id = :driverId AND b.isDeleted = false")
    Page<Bus> findByDriverIdAndIsDeletedFalse(@Param("driverId") Long driverId, Pageable pageable);

    // === ROTA SORGULARI ===

    @Query("SELECT b FROM Bus b WHERE b.assignedRoute.id = :routeId AND b.isDeleted = false")
    Page<Bus> findByAssignedRouteIdAndIsDeletedFalse(@Param("routeId") Long routeId, Pageable pageable);

    // === DURUM SORGULARI ===

    Page<Bus> findByStatusAndIsDeletedFalse(BusStatus status, Pageable pageable);

    // === İSTATİSTİK SORGULARI ===

    long countByIsDeletedFalse();

    long countByIsActiveTrueAndIsDeletedFalse();

    long countByIsActiveFalseAndIsDeletedFalse();

    long countByStatusAndIsDeletedFalse(BusStatus status);

    @Query("SELECT COUNT(b) FROM Bus b WHERE b.driver IS NOT NULL AND b.isDeleted = false")
    long countByDriverIsNotNullAndIsDeletedFalse();

    @Query("SELECT COUNT(b) FROM Bus b WHERE b.driver IS NULL AND b.isDeleted = false")
    long countByDriverIsNullAndIsDeletedFalse();

    @Query("SELECT COUNT(b) FROM Bus b WHERE b.assignedRoute IS NOT NULL AND b.isDeleted = false")
    long countByAssignedRouteIsNotNullAndIsDeletedFalse();

    @Query("SELECT COUNT(b) FROM Bus b WHERE b.assignedRoute IS NULL AND b.isDeleted = false")
    long countByAssignedRouteIsNullAndIsDeletedFalse();

    @Query("""
                SELECT b FROM Bus b
                WHERE b.assignedRoute = :route
                  AND b.isActive = true
                  AND b.isDeleted = false
            """)
    List<Bus> findAllByAssignedRouteAndIsActiveTrueAndIsDeletedFalse(@Param("route") Route route);

    List<Bus> findAllByIsActiveTrueAndIsDeletedFalseOrderById(Pageable pageable);

    @Query("SELECT b FROM Bus b JOIN FETCH b.assignedRoute WHERE b.id = :busId AND b.isDeleted = false")
    Optional<Bus> findByIdWithRoute(@Param("busId") Long busId);

    List<Bus> findByAssignedRouteAndIsActiveAndStatus(Route route, boolean b, BusStatus busStatus);
}
