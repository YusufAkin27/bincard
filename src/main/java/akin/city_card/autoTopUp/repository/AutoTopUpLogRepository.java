// AutoTopUpLogRepository.java
package akin.city_card.autoTopUp.repository;

import akin.city_card.autoTopUp.model.AutoTopUpConfig;
import akin.city_card.autoTopUp.model.AutoTopUpLog;
import akin.city_card.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AutoTopUpLogRepository extends JpaRepository<AutoTopUpLog, Long> {

    List<AutoTopUpLog> findByConfig(AutoTopUpConfig config);

    List<AutoTopUpLog> findByConfigOrderByTimestampDesc(AutoTopUpConfig config);

    List<AutoTopUpLog> findByConfigAndSuccess(AutoTopUpConfig config, boolean success);

    @Query("SELECT atl FROM AutoTopUpLog atl WHERE atl.config.user = :user ORDER BY atl.timestamp DESC")
    List<AutoTopUpLog> findByConfigUserOrderByTimestampDesc(@Param("user") User user);

    @Query("SELECT atl FROM AutoTopUpLog atl WHERE atl.config.user = :user AND atl.success = :success ORDER BY atl.timestamp DESC")
    List<AutoTopUpLog> findByConfigUserAndSuccessOrderByTimestampDesc(@Param("user") User user, @Param("success") boolean success);

    List<AutoTopUpLog> findByTimestampBetween(LocalDateTime startDate, LocalDateTime endDate);

    List<AutoTopUpLog> findByTimestampBetweenAndSuccess(LocalDateTime startDate, LocalDateTime endDate, boolean success);

    @Query("SELECT SUM(atl.amount) FROM AutoTopUpLog atl WHERE atl.config.user = :user AND atl.success = true")
    Double getTotalTopUpAmountByUser(@Param("user") User user);

    @Query("SELECT COUNT(atl) FROM AutoTopUpLog atl WHERE atl.config.user = :user AND atl.success = :success")
    long countByConfigUserAndSuccess(@Param("user") User user, @Param("success") boolean success);
}