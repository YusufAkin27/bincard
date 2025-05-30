package akin.city_card.notification.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
public class Notification {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private User user;

    private String message;
    private LocalDateTime sentAt;
    private boolean read;
}
