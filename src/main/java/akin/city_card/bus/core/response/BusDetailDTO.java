// BusDetailDTO.java - Detaylı otobüs bilgileri için
package akin.city_card.bus.core.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class BusDetailDTO extends BusDTO {

    // Genişletilmiş bilgiler
    private List<BusLocationDTO> recentLocations; // Son 10 konum
    private List<BusRideDTO> recentRides; // Son 20 yolculuk

    // Performans metrikleri
    private Double dailyDistance; // Günlük kat edilen mesafe
    private Integer dailyRideCount; // Günlük yolculuk sayısı
    private Double dailyRevenue; // Günlük gelir

    // Bakım bilgileri
    private LocalDateTime lastMaintenanceDate;
    private LocalDateTime nextMaintenanceDate;
    private Integer totalKilometers;

    // Şoför geçmişi
    private List<DriverHistoryDTO> driverHistory;
}
