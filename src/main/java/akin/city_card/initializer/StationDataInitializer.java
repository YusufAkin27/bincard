package akin.city_card.initializer;

import akin.city_card.paymentPoint.model.Address;
import akin.city_card.paymentPoint.model.Location;
import akin.city_card.station.model.Station;
import akin.city_card.station.model.StationType;
import akin.city_card.station.repository.StationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Random;
import java.util.stream.IntStream;

@Component
@RequiredArgsConstructor
@Order(7)
public class StationDataInitializer implements ApplicationRunner {

    private final StationRepository stationRepository;
    private final Random random = new Random();

    private static final double BINGOL_MIN_LAT = 38.8660;
    private static final double BINGOL_MAX_LAT = 38.8960;
    private static final double BINGOL_MIN_LNG = 40.4960;
    private static final double BINGOL_MAX_LNG = 40.5460;

    private String[] districts = {
            "Merkez", "Genç", "Solhan", "Karlıova", "Kiğı", "Yayladere", "Adaklı", "Yedisu"
    };

    @Override
    public void run(ApplicationArguments args) {
        if (stationRepository.count() > 0) return;

        IntStream.rangeClosed(20, 100).forEach(i -> {
            Station station = Station.builder()
                    .name("Bingöl Durağı " + i)
                    .location(generateRandomLocation())
                    .address(generateRandomAddress())
                    .type(StationType.OTOBUS)
                    .active(true)
                    .deleted(false)
                    .build();

            stationRepository.save(station);
        });

        System.out.println("✅ 100 adet Bingöl otobüs durağı oluşturuldu.");
    }

    private Location generateRandomLocation() {
        double latitude = BINGOL_MIN_LAT + (BINGOL_MAX_LAT - BINGOL_MIN_LAT) * random.nextDouble();
        double longitude = BINGOL_MIN_LNG + (BINGOL_MAX_LNG - BINGOL_MIN_LNG) * random.nextDouble();
        return new Location(latitude, longitude);
    }

    private Address generateRandomAddress() {
        String street = "Cumhuriyet Cad. No:" + (random.nextInt(100) + 1);
        String district = districts[random.nextInt(districts.length)];
        String city = "Bingöl";
        String postalCode = "12000";
        return new Address(street, district, city, postalCode);
    }
}

