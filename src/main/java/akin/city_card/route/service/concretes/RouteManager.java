package akin.city_card.route.service.concretes;

import akin.city_card.bus.exceptions.RouteNotFoundException;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.repository.BusRepository;
import akin.city_card.bus.service.abstracts.GoogleMapsService;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.core.converter.RouteConverter;
import akin.city_card.route.core.request.CreateRouteRequest;
import akin.city_card.route.core.request.CreateRouteStationRequest;
import akin.city_card.route.core.request.RouteSuggestionRequest;
import akin.city_card.route.core.response.*;
import akin.city_card.route.exceptions.RouteAlreadyFavoriteException;
import akin.city_card.route.exceptions.RouteNotActiveException;
import akin.city_card.route.model.*;
import akin.city_card.route.repository.RouteRepository;
import akin.city_card.route.service.abstracts.RouteService;
import akin.city_card.security.entity.Role;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.station.core.converter.StationConverter;
import akin.city_card.station.exceptions.StationNotFoundException;
import akin.city_card.station.model.Station;
import akin.city_card.station.repository.StationRepository;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class RouteManager implements RouteService {
    private static final double MAX_DISTANCE_KM = 0.5;

    private final RouteRepository routeRepository;
    private final RouteConverter routeConverter;
    private final SecurityUserRepository securityUserRepository;
    private final StationRepository stationRepository;
    private final UserRepository userRepository;
    private final GoogleMapsService googleMapsService;
    private final BusRepository busRepository;
    private final StationConverter stationConverter;

    @Override
    public DataResponseMessage<List<RouteNameDTO>> searchRoutesByName(String name) {
        List<Route> routes = routeRepository.searchByKeyword(name);
        List<RouteNameDTO> dtos = routes.stream()
                .filter(Route::isActive)
                .filter(route -> !route.isDeleted())
                .filter(route -> route.getDirections() != null && !route.getDirections().isEmpty())
                .map(routeConverter::toRouteNameDTO)
                .toList();

        return new DataResponseMessage<>("Arama sonuçları", true, dtos);
    }

    @Override
    @Transactional
    public ResponseMessage createBidirectionalRoute(String username, CreateRouteRequest request)
            throws UnauthorizedAreaException, StationNotFoundException {

        // 1. Kullanıcı yetki kontrolü
        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UnauthorizedAreaException::new);

        boolean isAdmin = securityUser.getRoles().contains(Role.ADMIN) ||
                securityUser.getRoles().contains(Role.SUPERADMIN);
        if (!isAdmin) {
            throw new UnauthorizedAreaException();
        }

        // 2. Durak kontrolü
        Station startStation = stationRepository.findById(request.getStartStationId())
                .orElseThrow(StationNotFoundException::new);
        Station endStation = stationRepository.findById(request.getEndStationId())
                .orElseThrow(StationNotFoundException::new);

        // 3. Ana rotayı oluştur
        Route route = new Route();
        route.setName(request.getRouteName());
        route.setCode(request.getRouteCode());
        route.setDescription(request.getDescription());
        route.setRouteType(request.getRouteType() != null ? request.getRouteType() : RouteType.CITY_BUS);
        route.setColor(request.getColor());
        route.setStartStation(startStation);
        route.setEndStation(endStation);
        route.setEstimatedDurationMinutes(request.getEstimatedDurationMinutes());
        route.setTotalDistanceKm(request.getTotalDistanceKm());
        route.setActive(true);
        route.setDeleted(false);
        route.setCreatedBy(securityUser);
        route.setUpdatedBy(securityUser);

        // 4. Schedule ayarla
        RouteSchedule schedule = new RouteSchedule();
        schedule.setWeekdayHours(request.getWeekdayHours());
        schedule.setWeekendHours(request.getWeekendHours());
        route.setSchedule(schedule);

        // 5. Gidiş yönünü oluştur
        RouteDirection outgoingDirection = createRouteDirection(
                route,
                DirectionType.GIDIS,
                startStation.getName() + " → " + endStation.getName(),
                startStation,
                endStation,
                request.getOutgoingStations()
        );

        // 6. Dönüş yönünü oluştur
        List<CreateRouteStationRequest> returnStations = request.getReturnStations();
        if (returnStations == null || returnStations.isEmpty()) {
            // Otomatik ters sıra oluştur
            returnStations = createReverseStations(request.getOutgoingStations(), endStation, startStation);
        }

        RouteDirection returnDirection = createRouteDirection(
                route,
                DirectionType.DONUS,
                endStation.getName() + " → " + startStation.getName(),
                endStation,
                startStation,
                returnStations
        );

        // 7. Yönleri rotaya ekle
        List<RouteDirection> directions = new ArrayList<>();
        directions.add(outgoingDirection);
        directions.add(returnDirection);
        route.setDirections(directions);

        // 8. Kaydet
        routeRepository.save(route);

        log.info("Bidirectional route created: {} with {} directions", route.getName(), directions.size());

        return new ResponseMessage("İki yönlü rota başarıyla oluşturuldu.", true);
    }

    private RouteDirection createRouteDirection(
            Route route,
            DirectionType type,
            String name,
            Station startStation,
            Station endStation,
            List<CreateRouteStationRequest> stationRequests) throws StationNotFoundException {

        RouteDirection direction = new RouteDirection();
        direction.setRoute(route);
        direction.setType(type);
        direction.setName(name);
        direction.setStartStation(startStation);
        direction.setEndStation(endStation);
        direction.setActive(true);

        // Station node'ları oluştur
        List<RouteStationNode> nodes = new ArrayList<>();
        int order = 0;
        int totalTime = 0;
        double totalDistance = 0.0;

        for (CreateRouteStationRequest stationRequest : stationRequests) {
            Station fromStation = stationRepository.findById(stationRequest.getFromStationId())
                    .orElseThrow(StationNotFoundException::new);
            Station toStation = stationRepository.findById(stationRequest.getToStationId())
                    .orElseThrow(StationNotFoundException::new);

            RouteStationNode node = new RouteStationNode();
            node.setDirection(direction);
            node.setFromStation(fromStation);
            node.setToStation(toStation);
            node.setSequenceOrder(order++);
            node.setEstimatedTravelTimeMinutes(stationRequest.getEstimatedTravelTimeMinutes());
            node.setDistanceKm(stationRequest.getDistanceKm());
            node.setNotes(stationRequest.getNotes());
            node.setActive(true);

            nodes.add(node);

            // Toplam süre ve mesafe hesapla
            if (stationRequest.getEstimatedTravelTimeMinutes() != null) {
                totalTime += stationRequest.getEstimatedTravelTimeMinutes();
            }
            if (stationRequest.getDistanceKm() != null) {
                totalDistance += stationRequest.getDistanceKm();
            }
        }

        direction.setStationNodes(nodes);
        direction.setEstimatedDurationMinutes(totalTime > 0 ? totalTime : null);
        direction.setTotalDistanceKm(totalDistance > 0 ? totalDistance : null);

        return direction;
    }

    private List<CreateRouteStationRequest> createReverseStations(
            List<CreateRouteStationRequest> originalStations,
            Station newStartStation,
            Station newEndStation) {

        List<CreateRouteStationRequest> reversed = new ArrayList<>();

        // Orijinal istasyonları ters çevir
        List<CreateRouteStationRequest> temp = new ArrayList<>(originalStations);
        Collections.reverse(temp);

        for (CreateRouteStationRequest original : temp) {
            CreateRouteStationRequest reversed_station = new CreateRouteStationRequest();
            // From ve To'yu ters çevir
            reversed_station.setFromStationId(original.getToStationId());
            reversed_station.setToStationId(original.getFromStationId());
            reversed_station.setEstimatedTravelTimeMinutes(original.getEstimatedTravelTimeMinutes());
            reversed_station.setDistanceKm(original.getDistanceKm());
            reversed_station.setNotes(original.getNotes());
            reversed.add(reversed_station);
        }

        return reversed;
    }

    @Override
    @Transactional
    public ResponseMessage deleteRoute(String username, Long id)
            throws UnauthorizedAreaException, RouteNotFoundException {

        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UnauthorizedAreaException::new);

        boolean isAdmin = securityUser.getRoles().contains(Role.ADMIN) ||
                securityUser.getRoles().contains(Role.SUPERADMIN);
        if (!isAdmin) {
            throw new UnauthorizedAreaException();
        }

        Route route = routeRepository.findById(id)
                .orElseThrow(RouteNotFoundException::new);

        route.setDeletedAt(LocalDateTime.now());
        route.setDeleted(true);
        route.setActive(false);
        route.setDeletedBy(securityUser);

        routeRepository.save(route);

        return new ResponseMessage("Rota başarıyla silindi", true);
    }

    @Override
    public DataResponseMessage<RouteDTO> getRouteById(Long id) throws RouteNotFoundException {
        Route route = routeRepository.findById(id)
                .orElseThrow(RouteNotFoundException::new);

        return new DataResponseMessage<>("Rota detayları", true, routeConverter.toRouteDTO(route));
    }

    @Override
    public DataResponseMessage<List<RouteNameDTO>> getAllRoutes() {
        List<RouteNameDTO> activeRoutes = routeRepository.findAll().stream()
                .filter(Route::isActive)
                .filter(route -> !route.isDeleted())
                .filter(route -> route.getDirections() != null && !route.getDirections().isEmpty())
                .map(routeConverter::toRouteNameDTO)
                .toList();

        return new DataResponseMessage<>("Aktif rotalar başarıyla listelendi.", true, activeRoutes);
    }

    @Override
    public DataResponseMessage<List<RouteDirectionDTO>> getRouteDirections(Long routeId)
            throws RouteNotFoundException {

        Route route = routeRepository.findById(routeId)
                .orElseThrow(RouteNotFoundException::new);

        List<RouteDirectionDTO> directionDTOs = route.getDirections().stream()
                .map(routeConverter::toRouteDirectionDTO)
                .toList();

        return new DataResponseMessage<>("Rota yönleri", true, directionDTOs);
    }

    @Override
    public DataResponseMessage<List<StationOrderDTO>> getStationsInDirection(Long routeId, DirectionType directionType)
            throws RouteNotFoundException {

        Route route = routeRepository.findById(routeId)
                .orElseThrow(RouteNotFoundException::new);

        RouteDirection direction = route.getDirections().stream()
                .filter(dir -> dir.getType() == directionType)
                .findFirst()
                .orElseThrow(() -> new RouteNotFoundException());

        List<StationOrderDTO> stations = new ArrayList<>();

        // İlk durağı ekle
        stations.add(StationOrderDTO.builder()
                .order(0)
                .station(stationConverter.toDTO(direction.getStartStation()))
                .estimatedTimeFromPrevious(0)
                .distanceFromPrevious(0.0)
                .isActive(true)
                .build());

        // Ara durakları ekle
        direction.getStationNodes().stream()
                .sorted((a, b) -> Integer.compare(a.getSequenceOrder(), b.getSequenceOrder()))
                .forEach(node -> {
                    stations.add(StationOrderDTO.builder()
                            .order(node.getSequenceOrder() + 1)
                            .station(stationConverter.toDTO(node.getToStation()))
                            .estimatedTimeFromPrevious(node.getEstimatedTravelTimeMinutes())
                            .distanceFromPrevious(node.getDistanceKm())
                            .isActive(node.isActive())
                            .build());
                });

        return new DataResponseMessage<>("Yöndeki duraklar", true, stations);
    }

    @Override
    public DataResponseMessage<List<RouteWithNextBusDTO>> findRoutesWithNextBus(Long stationId)
            throws StationNotFoundException {

        Station station = stationRepository.findById(stationId)
                .orElseThrow(StationNotFoundException::new);

        // Bu duraktan geçen rotaları bul
        List<Route> routes = findRoutesByStationId(stationId);
        List<RouteWithNextBusDTO> result = new ArrayList<>();

        for (Route route : routes) {
            // Bu rotadaki aktif otobüsleri bul
            List<Bus> activeBuses = findActiveBusesForRoute(route);

            // Her yön için en yakın otobüsü bul
            List<NextBusDTO> nextBuses = new ArrayList<>();

            for (RouteDirection direction : route.getDirections()) {
                List<Bus> directionBuses = activeBuses.stream()
                        .filter(bus -> direction.equals(bus.getCurrentDirection()))
                        .toList();

                Bus nearestBus = findNearestBusToStation(directionBuses, station);
                if (nearestBus != null) {
                    Integer eta = calculateETA(nearestBus, station);
                    if (eta != null && eta < 60) {
                        nextBuses.add(NextBusDTO.builder()
                                .plate(nearestBus.getNumberPlate())
                                .arrivalInMinutes(eta)
                                .direction(direction.getType())
                                .directionName(direction.getName())
                                .currentLocation(nearestBus.getLastSeenStation() != null ?
                                        nearestBus.getLastSeenStation().getName() : "Bilinmeyen")
                                .occupancyRate((int) nearestBus.getOccupancyRate())
                                .busStatus(nearestBus.getStatus().getDisplayName())
                                .build());
                    }
                }
            }

            RouteWithNextBusDTO dto = RouteWithNextBusDTO.builder()
                    .id(route.getId())
                    .name(route.getName())
                    .code(route.getCode())
                    .routeType(route.getRouteType().getDisplayName())
                    .startStationName(route.getStartStation().getName())
                    .endStationName(route.getEndStation().getName())
                    .routeSchedule(routeConverter.toRouteScheduleDTO(route.getSchedule()))
                    .nextBuses(nextBuses)
                    .totalActiveBuses(activeBuses.size())
                    .build();

            result.add(dto);
        }

        return new DataResponseMessage<>("Duraktan geçen rotalar", true, result);
    }

    @Override
    @Transactional
    public DataResponseMessage<RouteDTO> addStationToDirection(
            Long routeId,
            DirectionType directionType,
            Long afterStationId,
            Long newStationId,
            String username) throws StationNotFoundException, RouteNotFoundException {

        SecurityUser user = securityUserRepository.findByUserNumber(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Route route = routeRepository.findById(routeId)
                .orElseThrow(RouteNotFoundException::new);

        RouteDirection direction = route.getDirections().stream()
                .filter(dir -> dir.getType() == directionType)
                .findFirst()
                .orElseThrow(RouteNotFoundException::new);

        Station afterStation = stationRepository.findById(afterStationId)
                .orElseThrow(StationNotFoundException::new);
        Station newStation = stationRepository.findById(newStationId)
                .orElseThrow(StationNotFoundException::new);

        // Eski bağlantıyı bul ve böl
        RouteStationNode oldNode = direction.getStationNodes().stream()
                .filter(node -> node.getFromStation().equals(afterStation))
                .findFirst()
                .orElseThrow(StationNotFoundException::new);

        Station toStation = oldNode.getToStation();
        int oldOrder = oldNode.getSequenceOrder();

        // Eski node'u sil
        direction.getStationNodes().remove(oldNode);

        // Yeni node'ları oluştur
        RouteStationNode node1 = new RouteStationNode();
        node1.setDirection(direction);
        node1.setFromStation(afterStation);
        node1.setToStation(newStation);
        node1.setSequenceOrder(oldOrder);
        node1.setActive(true);

        RouteStationNode node2 = new RouteStationNode();
        node2.setDirection(direction);
        node2.setFromStation(newStation);
        node2.setToStation(toStation);
        node2.setSequenceOrder(oldOrder + 1);
        node2.setActive(true);

        direction.getStationNodes().add(node1);
        direction.getStationNodes().add(node2);

        // Sonraki node'ların sırasını güncelle
        direction.getStationNodes().stream()
                .filter(node -> node.getSequenceOrder() > oldOrder + 1)
                .forEach(node -> node.setSequenceOrder(node.getSequenceOrder() + 1));

        route.setUpdatedAt(LocalDateTime.now());
        route.setUpdatedBy(user);

        routeRepository.save(route);

        return new DataResponseMessage<>("Durak başarıyla eklendi", true, routeConverter.toRouteDTO(route));
    }

    @Override
    @Transactional
    public DataResponseMessage<RouteDTO> removeStationFromDirection(
            Long routeId,
            DirectionType directionType,
            Long stationId,
            String username) throws RouteNotFoundException, StationNotFoundException {

        SecurityUser user = securityUserRepository.findByUserNumber(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Route route = routeRepository.findById(routeId)
                .orElseThrow(RouteNotFoundException::new);

        RouteDirection direction = route.getDirections().stream()
                .filter(dir -> dir.getType() == directionType)
                .findFirst()
                .orElseThrow(RouteNotFoundException::new);

        Station stationToRemove = stationRepository.findById(stationId)
                .orElseThrow(StationNotFoundException::new);

        // Gelen ve giden bağlantıları bul
        Optional<RouteStationNode> incoming = direction.getStationNodes().stream()
                .filter(n -> n.getToStation().equals(stationToRemove))
                .findFirst();

        Optional<RouteStationNode> outgoing = direction.getStationNodes().stream()
                .filter(n -> n.getFromStation().equals(stationToRemove))
                .findFirst();

        if (incoming.isPresent() && outgoing.isPresent()) {
            RouteStationNode inNode = incoming.get();
            RouteStationNode outNode = outgoing.get();

            // Yeni bağlantı oluştur
            RouteStationNode newNode = new RouteStationNode();
            newNode.setDirection(direction);
            newNode.setFromStation(inNode.getFromStation());
            newNode.setToStation(outNode.getToStation());
            newNode.setSequenceOrder(inNode.getSequenceOrder());
            newNode.setActive(true);

            // Eski bağlantıları sil
            direction.getStationNodes().remove(inNode);
            direction.getStationNodes().remove(outNode);
            direction.getStationNodes().add(newNode);

            // Sonraki node'ların sırasını güncelle
            direction.getStationNodes().stream()
                    .filter(node -> node.getSequenceOrder() > inNode.getSequenceOrder())
                    .forEach(node -> node.setSequenceOrder(node.getSequenceOrder() - 1));
        } else {
            // Başlangıç veya bitiş durağı ise sadece ilgili bağlantıları sil
            direction.getStationNodes().removeIf(n ->
                    n.getFromStation().equals(stationToRemove) ||
                            n.getToStation().equals(stationToRemove));
        }

        route.setUpdatedAt(LocalDateTime.now());
        route.setUpdatedBy(user);

        routeRepository.save(route);

        return new DataResponseMessage<>("Durak başarıyla çıkarıldı", true, routeConverter.toRouteDTO(route));
    }

    @Override
    @Transactional
    public ResponseMessage addFavorite(String username, Long routeId)
            throws RouteNotActiveException, UserNotFoundException, RouteNotFoundException, RouteAlreadyFavoriteException {

        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);
        Route route = routeRepository.findById(routeId)
                .orElseThrow(RouteNotFoundException::new);

        if (!route.isActive() || route.isDeleted()) {
            throw new RouteNotActiveException();
        }

        if (user.getFavoriteRoutes() == null) {
            user.setFavoriteRoutes(new ArrayList<>());
        }

        boolean isPresent = user.getFavoriteRoutes().stream()
                .anyMatch(r -> r.getId().equals(route.getId()));

        if (isPresent) {
            throw new RouteAlreadyFavoriteException();
        }

        user.getFavoriteRoutes().add(route);
        userRepository.save(user);

        return new ResponseMessage("Rota favorilere eklendi", true);
    }

    @Override
    @Transactional
    public ResponseMessage removeFavorite(String username, Long routeId)
            throws RouteNotFoundException, UserNotFoundException, RouteNotActiveException {

        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);
        Route route = routeRepository.findById(routeId)
                .orElseThrow(RouteNotFoundException::new);

        if (!route.isActive() || route.isDeleted()) {
            throw new RouteNotActiveException();
        }

        if (user.getFavoriteRoutes() == null) {
            user.setFavoriteRoutes(new ArrayList<>());
        }

        boolean isDeleted = user.getFavoriteRoutes().removeIf(r -> r.getId().equals(route.getId()));
        userRepository.save(user);

        return new ResponseMessage("Rota favorilerden " + (isDeleted ? "çıkarıldı" : "çıkarılamadı"), true);
    }

    @Override
    public DataResponseMessage<List<RouteNameDTO>> favoriteRoutes(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        List<RouteNameDTO> favorites = user.getFavoriteRoutes().stream()
                .filter(Route::isActive)
                .filter(route -> !route.isDeleted())
                .map(routeConverter::toRouteNameDTO)
                .toList();

        return new DataResponseMessage<>("Favori rotalar", true, favorites);
    }

    @Override
    public DataResponseMessage<RouteSuggestionResponse> suggestRoute(RouteSuggestionRequest request) {
        log.info("Route suggestion started for user location: ({}, {}) and destination: {}",
                request.getUserLat(), request.getUserLng(), request.getDestinationAddress());

        GoogleMapsService.LatLng destinationLatLng = googleMapsService.getCoordinatesFromAddress(request.getDestinationAddress());
        if (destinationLatLng == null) {
            log.warn("Destination address '{}' could not be resolved to coordinates.", request.getDestinationAddress());
            return new DataResponseMessage<>("Hedef adres bulunamadı.", false, null);
        }

        List<Station> userNearbyStations = stationRepository.findAll().stream()
                .filter(st -> isWithinRadius(request.getUserLat(), request.getUserLng(),
                        st.getLocation().getLatitude(), st.getLocation().getLongitude(), MAX_DISTANCE_KM))
                .toList();

        List<Station> destinationNearbyStations = stationRepository.findAll().stream()
                .filter(st -> isWithinRadius(destinationLatLng.lat(), destinationLatLng.lng(),
                        st.getLocation().getLatitude(), st.getLocation().getLongitude(), MAX_DISTANCE_KM))
                .toList();

        for (Station userStation : userNearbyStations) {
            for (Station destStation : destinationNearbyStations) {
                List<Route> routes = findRoutesBetweenStations(userStation.getId(), destStation.getId());
                if (!routes.isEmpty()) {
                    Route matchedRoute = routes.get(0);

                    RouteSuggestionResponse response = RouteSuggestionResponse.builder()
                            .routeFound(true)
                            .message("Rota bulundu.")
                            .routeName(matchedRoute.getName())
                            .boardAt(userStation.getName())
                            .getOffAt(destStation.getName())
                            .googleMapUrl("https://maps.google.com/?q=" +
                                    destStation.getLocation().getLatitude() + "," +
                                    destStation.getLocation().getLongitude())
                            .build();

                    return new DataResponseMessage<>("Başarılı", true, response);
                }
            }
        }

        return new DataResponseMessage<>("Uygun rota bulunamadı.", false, null);
    }

    // Helper methods
    public List<Route> findRoutesByStationId(Long stationId) {
        return routeRepository.findAll().stream()
                .filter(Route::isActive)
                .filter(route -> !route.isDeleted())
                .filter(route -> route.getDirections().stream()
                        .anyMatch(direction -> direction.getStationNodes().stream()
                                .anyMatch(node -> node.getFromStation().getId().equals(stationId) ||
                                        node.getToStation().getId().equals(stationId)) ||
                                direction.getStartStation().getId().equals(stationId)))
                .toList();
    }

    @Override
    public List<Bus> findActiveBusesForRoute(Route route) {
        return busRepository.findAllByAssignedRouteAndIsActiveTrueAndIsDeletedFalse(route);
    }

    public Bus findNearestBusToStation(List<Bus> buses, Station station) {
        return buses.stream()
                .filter(bus -> bus.getCurrentLatitude() != null && bus.getCurrentLongitude() != null)
                .min((b1, b2) -> {
                    double dist1 = distanceKm(b1.getCurrentLatitude(), b1.getCurrentLongitude(),
                            station.getLocation().getLatitude(), station.getLocation().getLongitude());
                    double dist2 = distanceKm(b2.getCurrentLatitude(), b2.getCurrentLongitude(),
                            station.getLocation().getLatitude(), station.getLocation().getLongitude());
                    return Double.compare(dist1, dist2);
                })
                .orElse(null);
    }

    private Integer calculateETA(Bus bus, Station station) {
        if (bus.getCurrentLatitude() == null || bus.getCurrentLongitude() == null) {
            return null;
        }

        return googleMapsService.getEstimatedTimeInMinutes(
                bus.getCurrentLatitude(), bus.getCurrentLongitude(),
                station.getLocation().getLatitude(), station.getLocation().getLongitude()
        );
    }

    private List<Route> findRoutesBetweenStations(Long stationId1, Long stationId2) {
        return routeRepository.findAll().stream()
                .filter(Route::isActive)
                .filter(route -> !route.isDeleted())
                .filter(route -> route.getDirections().stream()
                        .anyMatch(direction -> {
                            List<Long> stationIds = new ArrayList<>();
                            stationIds.add(direction.getStartStation().getId());
                            direction.getStationNodes().forEach(node -> stationIds.add(node.getToStation().getId()));

                            int index1 = stationIds.indexOf(stationId1);
                            int index2 = stationIds.indexOf(stationId2);

                            return index1 >= 0 && index2 >= 0 && index1 < index2;
                        }))
                .toList();
    }

    private boolean isWithinRadius(double lat1, double lng1, double lat2, double lng2, double radiusKm) {
        double dist = distanceKm(lat1, lng1, lat2, lng2);
        return dist <= radiusKm;
    }

    private double distanceKm(double lat1, double lng1, double lat2, double lng2) {
        double R = 6371; // Dünya yarıçapı km
        double dLat = Math.toRadians(lat2 - lat1);
        double dLng = Math.toRadians(lng2 - lng1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
                        Math.sin(dLng / 2) * Math.sin(dLng / 2);
        return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    }
}