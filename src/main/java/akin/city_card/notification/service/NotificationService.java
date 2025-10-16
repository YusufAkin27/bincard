package akin.city_card.notification.service;

import akin.city_card.notification.core.response.NotificationDTO;
import akin.city_card.notification.exceptions.NotificationNotFoundException;
import akin.city_card.notification.exceptions.YouCanNotDeleteTheNotification;
import akin.city_card.notification.model.Notification;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.repository.NotificationRepository;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class NotificationService {

    private final NotificationRepository notificationRepository;
    private final UserRepository userRepository;

    // 🟢 Bildirim kaydetme
    @Transactional
    public Notification saveNotification(User user, String title, String message, NotificationType type, String targetUrl) {
        Notification notification = new Notification();
        notification.setUser(user);
        notification.setTitle(title);
        notification.setMessage(message);
        notification.setType(type);
        notification.setTargetUrl(targetUrl);
        notification.setSentAt(LocalDateTime.now());
        notification.setRead(false);
        notification.setDeleted(false);

        return notificationRepository.save(notification);
    }

    public Page<NotificationDTO> getNotifications(String username, Optional<NotificationType> type, Pageable pageable) throws UserNotFoundException {
        User user = getUserByUsernameOrThrow(username);

        Page<Notification> notifications;
        if (type.isPresent()) {
            notifications = notificationRepository.findByUserIdAndTypeAndDeletedFalseOrderBySentAtDesc(user.getId(), type.get(), pageable);
        } else {
            notifications = notificationRepository.findByUserIdAndDeletedFalseOrderBySentAtDesc(user.getId(), pageable);
        }

        return notifications.map(NotificationDTO::fromEntity);
    }


    @Transactional
    public Optional<NotificationDTO> getNotificationById(String username, Long notificationId) throws UserNotFoundException {
        User user = getUserByUsernameOrThrow(username);

        return notificationRepository.findByIdAndDeletedFalse(notificationId)
                .filter(notification -> notification.getUser().getId().equals(user.getId()))
                .map(notification -> {
                    if (!notification.isRead()) {
                        notification.setRead(true); // okunmuş olarak işaretle
                        notification.setReadAt(LocalDateTime.now()); // okunma zamanını ayarla
                        notificationRepository.save(notification);   // kaydet
                    }
                    return NotificationDTO.fromEntity(notification);
                });
    }


    @Transactional
    public void softDeleteNotification(String username, Long notificationId) throws UserNotFoundException, NotificationNotFoundException, YouCanNotDeleteTheNotification {
        User user = getUserByUsernameOrThrow(username);

        Notification notification = notificationRepository.findByIdAndDeletedFalse(notificationId)
                .orElseThrow(NotificationNotFoundException::new);

        if (!notification.getUser().getId().equals(user.getId())) {
            throw new YouCanNotDeleteTheNotification();
        }

        notification.setDeleted(true);
        notificationRepository.save(notification);
    }


    private User getUserByUsernameOrThrow(String username) throws UserNotFoundException {
        return userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);
    }

    public long countNotifications(String username, Optional<NotificationType> type) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        return type.map(notificationType -> notificationRepository.countByUserAndTypeAndDeletedFalseAndIsReadFalse(user, notificationType)).orElseGet(() -> notificationRepository.countByUserAndDeletedFalseAndIsReadFalse(user));
    }


}
