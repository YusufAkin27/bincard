package akin.city_card.notification.controller;

import akin.city_card.notification.core.response.NotificationDTO;
import akin.city_card.notification.exceptions.NotificationNotFoundException;
import akin.city_card.notification.exceptions.YouCanNotDeleteTheNotification;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.service.NotificationService;
import akin.city_card.security.exception.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/v1/api/notifications")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('USER')")
public class NotificationController {

    private final NotificationService notificationService;

    @GetMapping
    public ResponseEntity<Page<NotificationDTO>> getNotifications(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam Optional<NotificationType> type,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) throws UserNotFoundException {
        Pageable pageable = PageRequest.of(page, size);
        Page<NotificationDTO> notifications = notificationService.getNotifications(userDetails.getUsername(), type, pageable);
        return ResponseEntity.ok(notifications);
    }

    // 📄 Bildirim detayı
    @GetMapping("/{id}")
    public ResponseEntity<NotificationDTO> getNotificationDetail(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id) throws UserNotFoundException {
        return ResponseEntity.of(notificationService.getNotificationById(userDetails.getUsername(), id));
    }

    // ❌ Bildirim silme (soft delete)
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteNotification(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id) throws UserNotFoundException, YouCanNotDeleteTheNotification, NotificationNotFoundException {
        notificationService.softDeleteNotification(userDetails.getUsername(), id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/count")
    public ResponseEntity<Long> getNotificationCount(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam Optional<NotificationType> type
    ) throws UserNotFoundException {
        long count = notificationService.countNotifications(userDetails.getUsername(), type);
        return ResponseEntity.ok(count);
    }

}
