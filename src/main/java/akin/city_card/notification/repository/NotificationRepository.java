package akin.city_card.notification.repository;

import akin.city_card.notification.model.Notification;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.user.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface NotificationRepository extends JpaRepository<Notification, Long> {
    Page<Notification> findByUserIdAndDeletedFalseOrderBySentAtDesc(Long userId, Pageable pageable);

    Page<Notification> findByUserIdAndTypeAndDeletedFalseOrderBySentAtDesc(Long userId, NotificationType type, Pageable pageable);

    Optional<Notification> findByIdAndDeletedFalse(Long id);

    long countByUserAndDeletedFalseAndIsReadFalse(User user);

    long countByUserAndTypeAndDeletedFalseAndIsReadFalse(User user, NotificationType type);

}
