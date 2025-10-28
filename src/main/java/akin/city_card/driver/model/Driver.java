package akin.city_card.driver.model;

import akin.city_card.bus.model.Bus;
import akin.city_card.security.entity.SecurityUser;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class Driver extends SecurityUser {

    @Column(unique = true, nullable = false, length = 11)
    private String nationalId;

    @Column(unique = true, nullable = false)
    private String cardUid;

    @Column(nullable = false)
    private LocalDate dateOfBirth;

    private LocalDate employmentDate;

    private LocalDate licenseIssueDate;

    private String licenseClass;

    private String licenseNumber;

    private LocalDate licenseExpiryDate;

    private String address;

    @Enumerated(EnumType.STRING)
    private Shift shift;

    @OneToOne(mappedBy = "driver")
    private Bus assignedBus;

    @OneToMany(mappedBy = "driver", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<DriverShiftLog> shiftLogs;

    // Toplam sürüş saati
    private Long totalDrivingHours;

    // Toplam mesafe (km)
    private Double totalDistanceDriven;

    // Toplam yolcu taşıma sayısı
    private Long totalPassengersTransported;

    // Toplam kazanç
    private BigDecimal totalEarnings;

    // Ortalama puan (yolcu değerlendirmelerine göre)
    private Double averageRating;

    // Aktif mi (işten ayrıldıysa false olur)
    private Boolean active = true;

    // Sağlık raporu son geçerlilik tarihi
    private LocalDate healthCertificateExpiry;

    // Ceza kayıtları
    @OneToMany(mappedBy = "driver", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<DriverPenalty> penalties;

    // Evraklar (belge dosyaları vs.)
    @OneToMany(mappedBy = "driver", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<DriverDocument> documents;


    @ManyToOne
    @JoinColumn(name = "created_by_id")
    private SecurityUser createdBy;

    @ManyToOne
    @JoinColumn(name = "updated_by_id")
    private SecurityUser updatedBy;

    @ManyToOne
    @JoinColumn(name = "deleted_by_id")
    private SecurityUser deletedBy;
    private LocalDateTime createDate;
    private LocalDateTime updateDate;
    private LocalDateTime deleteDate;

    @PrePersist
    protected void onHire() {
        if (employmentDate == null) {
            employmentDate = LocalDate.now();
        }
        if (createDate == null) {
            createDate = LocalDateTime.now();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updateDate = LocalDateTime.now();
    }

    @PreRemove
    protected void onDelete() {
        deleteDate = LocalDateTime.now();
    }
}
