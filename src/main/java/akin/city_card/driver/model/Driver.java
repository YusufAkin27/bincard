package akin.city_card.driver.model;

import akin.city_card.bus.model.Bus;
import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDate;
import java.util.List;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class Driver extends SecurityUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Şoförün adı
    @Column(nullable = false)
    private String name;

    // Şoförün soyadı
    @Column(nullable = false)
    private String surname;

    // T.C. Kimlik Numarası — benzersiz olmalı
    @Column(unique = true, nullable = false, length = 11)
    private String identityNumber;

    // İletişim numarası (zorunlu değil, ayrı tutulmuş)
    private String phoneNumber;

    // E-posta adresi
    private String email;

    // Doğum tarihi
    @Column(nullable = false)
    private LocalDate dateOfBirth;

    // İşe başlama tarihi
    private LocalDate employmentDate;

    // Ehliyetin verildiği tarih
    private LocalDate licenseIssueDate;

    // Ehliyet sınıfı: Örn. D, E, CE
    private String licenseClass;

    // Şoför aktif mi? İşten çıkarıldıysa false yapılabilir
    private boolean active = true;

    // İkamet adresi
    private String address;

    // Profil fotoğrafı (URL formatında saklanır)
    private String photoUrl;

    // Güncel vardiya bilgisi (örn. SABAH, AKŞAM)
    @Enumerated(EnumType.STRING)
    private Shift shift;

    // Şoföre atanan otobüs (eğer bire bir ilişki gerekiyorsa)
    @OneToOne(mappedBy = "driver")
    private Bus assignedBus;

    // Şoförün vardiya geçmişi kayıtları
    @OneToMany(mappedBy = "driver", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<DriverShiftLog> shiftLogs;

    // Şoför ilk kez kaydedilirken işe başlama tarihi boşsa bugünün tarihi atanır
    @PrePersist
    protected void onHire() {
        if (employmentDate == null) {
            employmentDate = LocalDate.now();
        }
    }
}
