package akin.city_card.user.model;

import akin.city_card.card.model.Card;
import akin.city_card.wallet.model.Wallet;
import jakarta.persistence.*;

import java.util.List;



import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.management.relation.Role;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "users") // 'user' bazı DB’lerde rezerve kelimedir
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50)
    private String name;

    @Column(nullable = false, length = 50)
    private String surname;

    @Column(unique = true, nullable = false, length = 11)
    private String phoneNumber;

    @Column(nullable = false)
    private String password;

    private Role role;

    private boolean active = true;

    private boolean phoneVerified = false;

    private boolean emailVerified = false;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Card> cards;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private Wallet wallet;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<VerificationCode> verificationCodes;

}
