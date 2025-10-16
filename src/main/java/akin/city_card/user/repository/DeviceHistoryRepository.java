package akin.city_card.user.repository;

import akin.city_card.security.entity.SecurityUser;
import akin.city_card.user.model.DeviceHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface DeviceHistoryRepository extends JpaRepository<DeviceHistory, Long> {

    // Kullanıcının tüm cihazları
    List<DeviceHistory> findByUserAndIsDeletedFalseOrderByLastSeenAtDesc(SecurityUser user);

    // Kullanıcının aktif cihazları
    List<DeviceHistory> findByUserAndIsActiveAndIsDeletedFalseOrderByLastActiveAtDesc(SecurityUser user, Boolean isActive);

    // Kullanıcının güvenilir cihazları
    List<DeviceHistory> findByUserAndIsTrustedAndIsDeletedFalse(SecurityUser user, Boolean isTrusted);

    // Belirli deviceId'ye sahip cihaz
    Optional<DeviceHistory> findByUserAndDeviceIdAndIsDeletedFalse(SecurityUser user, String deviceId);

    // IP adresine göre arama
    List<DeviceHistory> findByIpAddressAndIsDeletedFalse(String ipAddress);

    // Engellenmiş cihazlar
    Page<DeviceHistory> findByIsBannedAndIsDeletedFalse(Boolean isBanned, Pageable pageable);

    // Son aktivite zamanına göre filtreleme
    @Query("SELECT dh FROM DeviceHistory dh WHERE dh.user = :user AND dh.lastActiveAt >= :since AND dh.isDeleted = false")
    List<DeviceHistory> findActiveDevicesSince(@Param("user") SecurityUser user, @Param("since") LocalDateTime since);

    // Şüpheli cihazlar (çok fazla IP değişimi olan)
    @Query("SELECT dh FROM DeviceHistory dh WHERE dh.user = :user AND dh.loginCount > :threshold AND dh.isDeleted = false")
    List<DeviceHistory> findSuspiciousDevices(@Param("user") SecurityUser user, @Param("threshold") Long threshold);

    // Belirli tarih aralığında aktif olan cihazlar
    @Query("SELECT dh FROM DeviceHistory dh WHERE dh.lastActiveAt BETWEEN :startDate AND :endDate AND dh.isDeleted = false")
    Page<DeviceHistory> findDevicesActiveBetween(@Param("startDate") LocalDateTime startDate,
                                                 @Param("endDate") LocalDateTime endDate,
                                                 Pageable pageable);
}