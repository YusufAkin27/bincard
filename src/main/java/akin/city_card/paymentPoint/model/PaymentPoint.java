package akin.city_card.paymentPoint.model;

import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
public class PaymentPoint {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String name;


    private double latitude;

    private double longitude;

    @Column(length = 20)
    private String contactNumber;


    @Column(length = 50)
    private String workingHours;

    @Column(length = 255)
    private String paymentMethods;

    @Column(length = 500)
    private String description;

    private boolean active = true;

    @UpdateTimestamp
    private LocalDateTime lastUpdated;
}
