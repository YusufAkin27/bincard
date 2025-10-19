package akin.city_card.bus.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BusStatisticsDTO {

    // Genel sayılar
    private Long totalBuses;
    private Long activeBuses;
    private Long inactiveBuses;
    private Long deletedBuses;

    // Durum dağılımı
    private Map<String, Long> statusDistribution;

    // Şoför durumu
    private Long busesWithDriver;
    private Long busesWithoutDriver;

    // Rota durumu
    private Long busesWithRoute;
    private Long busesWithoutRoute;

    // Kapasite bilgileri
    private Integer totalCapacity;
    private Integer averageCapacity;
    private Integer minCapacity;
    private Integer maxCapacity;

    // Ücret bilgileri
    private Double averageFare;
    private Double minFare;
    private Double maxFare;

    // Doluluk oranları
    private Double averageOccupancyRate;
    private Long fullBuses;
    private Long emptyBuses;
}