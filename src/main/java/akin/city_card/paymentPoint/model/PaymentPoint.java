package akin.city_card.paymentPoint.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "payment_points")
@Data
@AllArgsConstructor
@Builder
@NoArgsConstructor
public class PaymentPoint {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 150, columnDefinition = "VARCHAR(150)")
    private String name;

    @Column(length = 100, columnDefinition = "VARCHAR(100)")
    private String workingHours;

    @Embedded
    private Location location;

    @Embedded
    private Address address;

    @Column(length = 20)
    private String contactNumber;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "payment_point_methods", joinColumns = @JoinColumn(name = "payment_point_id"))
    @Column(name = "payment_method")
    private List<PaymentMethod> paymentMethods;

    @Column(length = 1000)
    private String description;

    private boolean active = true;

    @OneToMany(mappedBy = "paymentPoint", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<PaymentPhoto> photos;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime lastUpdated;

}
