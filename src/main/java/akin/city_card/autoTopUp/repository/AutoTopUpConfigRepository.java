// AutoTopUpConfigRepository.java
package akin.city_card.autoTopUp.repository;

import akin.city_card.autoTopUp.model.AutoTopUpConfig;
import akin.city_card.buscard.model.BusCard;
import akin.city_card.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AutoTopUpConfigRepository extends JpaRepository<AutoTopUpConfig, Long> {

    List<AutoTopUpConfig> findByUser(User user);

    List<AutoTopUpConfig> findByUserAndActive(User user, boolean active);

    List<AutoTopUpConfig> findByUserAndActiveOrderByCreatedAtDesc(User user, boolean active);

    List<AutoTopUpConfig> findByActive(boolean active);

    Optional<AutoTopUpConfig> findByIdAndUser(Long id, User user);

    Optional<AutoTopUpConfig> findByBusCardAndActive(BusCard busCard, boolean active);

    boolean existsByBusCardAndActive(BusCard busCard, boolean active);

    boolean existsByUserAndBusCardAndActive(User user, BusCard busCard, boolean active);

    @Query("SELECT atc FROM AutoTopUpConfig atc WHERE atc.active = true AND atc.busCard.balance <= atc.threshold")
    List<AutoTopUpConfig> findConfigsNeedingTopUp();

    @Query("SELECT COUNT(atc) FROM AutoTopUpConfig atc WHERE atc.user = :user AND atc.active = true")
    long countActiveConfigsByUser(@Param("user") User user);

    @Query("SELECT atc FROM AutoTopUpConfig atc WHERE atc.lastTopUpAt BETWEEN :startDate AND :endDate")
    List<AutoTopUpConfig> findByLastTopUpAtBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);
}
