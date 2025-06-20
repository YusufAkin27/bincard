package akin.city_card.user.model;

import akin.city_card.buscard.model.BusCard;
import akin.city_card.user.model.User;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GeoAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Hangi kullanıcıya ait
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Opsiyonel olarak hangi kartla ilişkili
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "bus_card_id")
    private BusCard busCard;

    private double latitude;

    private double longitude;

    private double radiusMeters = 300; // Varsayılan olarak 300m

    private int notifyBeforeMinutes = 5;

    private boolean active = true;

    private String alertName; // Kullanıcı dostu isim


}
