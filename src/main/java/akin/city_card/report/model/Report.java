package akin.city_card.report.model;

import akin.city_card.user.model.User;
import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
public class Report {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private User user;

    private String category; // örn: "Kayıp eşya", "Şoför şikayeti"

    private String message;

    private LocalDateTime createdAt;

    private boolean resolved = false;
}
