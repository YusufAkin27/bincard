package akin.city_card.user.model;

import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_identity_info")
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class UserIdentityInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "front_card_photo")
    private String frontCardPhoto;

    @Column(name = "back_card_photo")
    private String backCardPhoto;

    @Column(name = "national_id", length = 11, unique = true, nullable = false)
    private String nationalId;

    @Column(name = "serial_number", length = 9)
    private String serialNumber;

    @Column(name = "birth_date")
    private LocalDate birthDate;

    @Column(name = "gender", length = 10)
    private String gender;

    @Column(name = "mother_name", length = 100)
    private String motherName;

    @Column(name = "father_name", length = 100)
    private String fatherName;

    // Onayı yapan admin/superadmin (SecurityUser ile ManyToOne ilişkisi)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approved_by_id")
    private SecurityUser approvedBy;

    @Column(name = "is_approved")
    private Boolean approved;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", unique = true)
    private User user;

}
