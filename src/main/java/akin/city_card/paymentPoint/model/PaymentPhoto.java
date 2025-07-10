package akin.city_card.paymentPoint.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "payment_point_photos")
@Data
public class PaymentPhoto {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 500)
    private String imageUrl;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "payment_point_id")
    private PaymentPoint paymentPoint;
}
