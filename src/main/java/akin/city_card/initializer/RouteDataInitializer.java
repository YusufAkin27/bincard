package akin.city_card.initializer;

import akin.city_card.route.model.*;
import akin.city_card.route.repository.RouteRepository;
import akin.city_card.route.repository.RouteStationNodeRepository;
import akin.city_card.station.model.Station;
import akin.city_card.station.repository.StationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

@Component
@RequiredArgsConstructor
@Order(8)
public class RouteDataInitializer implements ApplicationRunner {

    private final StationRepository stationRepository;
    private final RouteRepository routeRepository;
    private final RouteStationNodeRepository routeStationNodeRepository;
    private final Random random = new Random();

    @Override
    public void run(ApplicationArguments args) {
        if (routeRepository.count() > 0) return;

        List<Station> allStations = stationRepository.findAll();
        if (allStations.size() < 20) {
            System.out.println("🚫 Yeterli sayıda durak yok. Rota oluşturulmadı.");
            return;
        }

        for (int i = 0; i < 30; i++) {
            List<Station> routeStations = selectNearbyStations(allStations, 20);
            if (routeStations.size() < 2) continue;

            String routeName = getRandomRouteName();
            String routeCode = generateRouteCode(i);

            Route route = new Route();
            route.setName("Rota - " + routeName);
            route.setCode(routeCode);
            route.setStartStation(routeStations.get(0));
            route.setEndStation(routeStations.get(routeStations.size() - 1));
            route.setColor(generateColor());
            route.setEstimatedDurationMinutes(45 + random.nextInt(20));
            route.setTotalDistanceKm(5.0 + random.nextDouble(10.0));
            route.setRouteType(RouteType.CITY_BUS);
            route.setSchedule(generateRandomSchedule());
            route.setCreatedAt(LocalDateTime.now());
            route.setUpdatedAt(LocalDateTime.now());
            route.setActive(true);
            route.setDeleted(false);
            routeRepository.save(route);

            // Yönleri oluştur
            RouteDirection gidis = createRouteDirection(route, DirectionType.GIDIS, routeStations);
            RouteDirection donus = createRouteDirection(route, DirectionType.DONUS, reverseList(routeStations));

            route.setDirections(List.of(gidis, donus));
            routeRepository.save(route);
        }

        System.out.println("✅ 30 rota başarıyla oluşturuldu.");
    }

    private RouteDirection createRouteDirection(Route route, DirectionType type, List<Station> stations) {
        RouteDirection direction = new RouteDirection();
        direction.setRoute(route);
        direction.setType(type);
        direction.setName(type == DirectionType.GIDIS ?
                stations.get(0).getName() + " → " + stations.get(stations.size() - 1).getName() :
                stations.get(0).getName() + " → " + stations.get(stations.size() - 1).getName());
        direction.setStartStation(stations.get(0));
        direction.setEndStation(stations.get(stations.size() - 1));
        direction.setEstimatedDurationMinutes(45 + random.nextInt(20));
        direction.setTotalDistanceKm(5.0 + random.nextDouble(10.0));
        direction.setActive(true);

        List<RouteStationNode> nodes = new ArrayList<>();
        for (int i = 0; i < stations.size() - 1; i++) {
            RouteStationNode node = new RouteStationNode();
            node.setDirection(direction);
            node.setFromStation(stations.get(i));
            node.setToStation(stations.get(i + 1));
            node.setSequenceOrder(i);
            node.setDistanceKm(0.3 + random.nextDouble(2.0));
            node.setEstimatedTravelTimeMinutes(3 + random.nextInt(7));
            node.setActive(true);
            nodes.add(node);
        }

        direction.setStationNodes(nodes);
        return direction;
    }

    private List<Station> selectNearbyStations(List<Station> allStations, int count) {
        Station start = allStations.get(random.nextInt(allStations.size()));
        List<Station> result = new ArrayList<>();
        result.add(start);

        Set<Station> used = new HashSet<>(result);

        while (result.size() < count) {
            Station last = result.get(result.size() - 1);

            Station next = allStations.stream()
                    .filter(s -> !used.contains(s))
                    .sorted(Comparator.comparingDouble(s -> distance(last, s)))
                    .findFirst()
                    .orElse(null);

            if (next == null) break;

            result.add(next);
            used.add(next);
        }

        return result;
    }

    private double distance(Station a, Station b) {
        double latDiff = a.getLocation().getLatitude() - b.getLocation().getLatitude();
        double lonDiff = a.getLocation().getLongitude() - b.getLocation().getLongitude();
        return Math.sqrt(latDiff * latDiff + lonDiff * lonDiff);
    }

    private String getRandomRouteName() {
        String[] names = {"Akasya", "Nilüfer", "Yavuz", "Meşe", "Zeytin", "Pınar", "Kartal", "Serin", "Çamlık", "Güneş"};
        return names[random.nextInt(names.length)] + "-" + (100 + random.nextInt(900));
    }

    private String generateRouteCode(int index) {
        return "R" + (100 + index);
    }

    private String generateColor() {
        String[] colors = {"#FF5733", "#33A1FF", "#6AFF33", "#FFC300", "#C70039", "#900C3F", "#581845"};
        return colors[random.nextInt(colors.length)];
    }

    private RouteSchedule generateRandomSchedule() {
        List<TimeSlot> all = Arrays.asList(TimeSlot.values());
        Collections.shuffle(all);
        List<TimeSlot> weekday = new ArrayList<>(all.subList(0, Math.min(all.size(), 8)));
        Collections.shuffle(all);
        List<TimeSlot> weekend = new ArrayList<>(all.subList(0, Math.min(all.size(), 5)));

        return new RouteSchedule(weekday, weekend);
    }

    private List<Station> reverseList(List<Station> list) {
        List<Station> reversed = new ArrayList<>(list);
        Collections.reverse(reversed);
        return reversed;
    }
}
