package akin.city_card.driver.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DriverDocument {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String documentName;
    private String documentType;
    private LocalDate expiryDate;

    // Belgeler bir dosya yoluyla saklanabilir veya başka bir servis ile entegre edilebilir
    private String filePath;

    @ManyToOne
    @JoinColumn(name = "driver_id")
    private Driver driver;
}
