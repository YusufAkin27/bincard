package akin.city_card.initializer;

import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusStatus;
import akin.city_card.bus.repository.BusRepository;
import akin.city_card.driver.model.Driver;
import akin.city_card.driver.repository.DriverRepository;
import akin.city_card.route.model.Route;
import akin.city_card.route.repository.RouteRepository;
import akin.city_card.station.model.Station;
import akin.city_card.station.repository.StationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Order(9)
public class BusDataInitializer implements ApplicationRunner {

    private final BusRepository busRepository;
    private final DriverRepository driverRepository;
    private final RouteRepository routeRepository;
    private final StationRepository stationRepository;

    private final Random random = new Random();

    @Override
    public void run(ApplicationArguments args) {
        if (busRepository.count() > 0) return;

        List<Driver> drivers = driverRepository.findAll();
        List<Route> routes = routeRepository.findAll();
        List<Station> stations = stationRepository.findAll();

        if (!isInitialDataValid(drivers, routes, stations)) return;

        Set<Integer> usedDriverIndexes = new HashSet<>();

        int createdCount = 0;
        while (createdCount < 100 && usedDriverIndexes.size() < drivers.size()) {
            int driverIndex = random.nextInt(drivers.size());
            if (usedDriverIndexes.contains(driverIndex)) continue;

            usedDriverIndexes.add(driverIndex);
            Route route = routes.get(random.nextInt(routes.size()));
            Station startStation = stations.get(random.nextInt(stations.size()));

            Bus bus = new Bus();
            bus.setDriver(null);
            bus.setAssignedRoute(route);
            bus.setNumberPlate(generatePlate(createdCount));
            bus.setLastKnownSpeed(20.0 + random.nextInt(20));
            bus.setStatus(BusStatus.CALISIYOR);
            bus.setLastSeenStation(startStation);
            bus.setLastSeenStation(startStation);
            bus.setCurrentLatitude(startStation.getLocation().getLatitude());
            bus.setCurrentLongitude(startStation.getLocation().getLongitude());
            bus.setLastLocationUpdate(LocalDateTime.now());
            bus.setCreatedAt(LocalDateTime.now());
            bus.setUpdatedAt(LocalDateTime.now());

            busRepository.save(bus);
            createdCount++;
        }

        System.out.println("✅ " + createdCount + " otobüs başarıyla oluşturuldu.");
    }

    private boolean isInitialDataValid(List<Driver> drivers, List<Route> routes, List<Station> stations) {
        if (drivers.size() < 100) {
            System.out.println("🚫 Yeterli sürücü bulunamadı. Otobüsler oluşturulmadı.");
            return false;
        }
        if (routes.isEmpty()) {
            System.out.println("🚫 Rota bilgisi bulunamadı. Otobüsler oluşturulmadı.");
            return false;
        }
        if (stations.isEmpty()) {
            System.out.println("🚫 Durak bilgisi bulunamadı. Otobüsler oluşturulmadı.");
            return false;
        }
        return true;
    }

    private String generatePlate(int index) {
        String[] cities = {"34", "06", "35", "16", "01", "44", "23", "61"};
        String cityCode = cities[random.nextInt(cities.length)];
        char letter1 = (char) ('A' + random.nextInt(26));
        char letter2 = (char) ('A' + random.nextInt(26));
        int digits = 100 + random.nextInt(900);

        return cityCode + " " + letter1 + letter2 + " " + digits;
    }
}
