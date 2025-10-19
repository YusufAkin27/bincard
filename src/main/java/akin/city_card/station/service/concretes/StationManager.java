package akin.city_card.station.service.concretes;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.service.abstracts.GoogleMapsService;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.paymentPoint.model.Address;
import akin.city_card.paymentPoint.model.Location;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.core.converter.RouteConverter;
import akin.city_card.route.core.response.NextBusDTO;
import akin.city_card.route.core.response.PublicRouteDTO;
import akin.city_card.route.core.response.RouteWithNextBusDTO;
import akin.city_card.route.model.DirectionType;
import akin.city_card.route.model.Route;
import akin.city_card.route.model.RouteDirection;
import akin.city_card.route.model.RouteStationNode;
import akin.city_card.route.repository.RouteRepository;
import akin.city_card.route.service.abstracts.RouteService;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.station.core.converter.StationConverter;
import akin.city_card.station.core.request.CreateStationRequest;
import akin.city_card.station.core.request.SearchStationRequest;
import akin.city_card.station.core.request.UpdateStationRequest;
import akin.city_card.station.core.response.RoutePosition;
import akin.city_card.station.core.response.StationDetailsDTO;
import akin.city_card.station.exceptions.StationNotActiveException;
import akin.city_card.station.exceptions.StationNotFoundException;
import akin.city_card.station.model.Station;
import akin.city_card.station.model.StationType;
import akin.city_card.station.repository.StationRepository;
import akin.city_card.station.service.abstracts.StationService;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class StationManager implements StationService {
    private final StationRepository stationRepository;
    private final UserRepository userRepository;
    private final SecurityUserRepository securityUserRepository;
    private final StationConverter stationConverter;
    private final RouteRepository routeRepository;
    private final RouteConverter routeConverter;
    private final RouteService routeService;
    private final GoogleMapsService googleMapsService;

    @Override
    @Transactional
    public DataResponseMessage<StationDTO> createStation(UserDetails userDetails, CreateStationRequest request) throws AdminNotFoundException, UnauthorizedAreaException {
        if (!isAdminOrSuperAdmin(userDetails)) {
            throw new UnauthorizedAreaException();
        }
        Station station = Station.builder()
                .name(request.getName())
                .type(request.getType())
                .location(new Location(request.getLatitude(), request.getLongitude()))
                .address(Address.builder()
                        .city(request.getCity())
                        .district(request.getDistrict())
                        .street(request.getStreet())
                        .postalCode(request.getPostalCode())
                        .build())
                .active(true)
                .deleted(false)
                .createdBy(securityUserRepository.findByUserNumber(userDetails.getUsername())
                        .orElseThrow(AdminNotFoundException::new))
                .createdDate(LocalDateTime.now())
                .updatedDate(LocalDateTime.now())
                .build();

        station = stationRepository.save(station);
        return new DataResponseMessage<>("Durak başarıyla eklendi.", true, stationConverter.toDTO(station));
    }

    @Override
    @Transactional
    public DataResponseMessage<StationDTO> updateStation(String username, UpdateStationRequest request) {
        Station station = stationRepository.findById(request.getId())
                .orElseThrow(() -> new EntityNotFoundException("Durak bulunamadı."));

        if (request.getName() != null) station.setName(request.getName());
        if (request.getLatitude() != null && request.getLongitude() != null) {
            station.setLocation(new Location(request.getLatitude(), request.getLongitude()));
        }
        if (request.getType() != null) station.setType(request.getType());

        if (station.getAddress() == null) station.setAddress(new Address());

        if (request.getCity() != null) station.getAddress().setCity(request.getCity());
        if (request.getDistrict() != null) station.getAddress().setDistrict(request.getDistrict());
        if (request.getStreet() != null) station.getAddress().setStreet(request.getStreet());
        if (request.getPostalCode() != null) station.getAddress().setPostalCode(request.getPostalCode());

        if (request.getActive() != null) station.setActive(request.getActive());

        station.setUpdatedDate(LocalDateTime.now());
        stationRepository.save(station);

        return new DataResponseMessage<>("Durak başarıyla güncellendi.", true, stationConverter.toDTO(station));
    }

    @Override
    @Transactional
    public DataResponseMessage<StationDTO> changeStationStatus(Long id, boolean active, String username) {
        Station station = stationRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Durak bulunamadı."));
        station.setActive(active);
        station.setUpdatedDate(LocalDateTime.now());
        stationRepository.save(station);
        return new DataResponseMessage<>("Durak durumu güncellendi.", true, stationConverter.toDTO(station));
    }

    @Override
    @Transactional
    public ResponseMessage deleteStation(Long id, String username) {
        Station station = stationRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Durak bulunamadı."));
        station.setDeleted(true);
        station.setActive(false);
        station.setUpdatedDate(LocalDateTime.now());
        stationRepository.save(station);
        return new ResponseMessage("Durak başarıyla silindi.", true);
    }

    @Override
    public DataResponseMessage<PageDTO<StationDTO>> getAllStations(Double latitude, Double longitude, StationType type, int page, int size) {
        List<Station> stations = stationRepository.findAll()
                .stream()
                .filter(s -> !s.isDeleted() && s.isActive())
                .filter(type != null ? s -> s.getType().equals(type) : s -> true)
                .sorted((latitude != null && longitude != null)
                        ? Comparator.comparingDouble(s -> distance(latitude, longitude,
                        s.getLocation().getLatitude(), s.getLocation().getLongitude()))
                        : Comparator.comparing(Station::getId) // alternatif sıralama
                )
                .toList();

        int totalElements = stations.size();
        int totalPages = (int) Math.ceil((double) totalElements / size);

        int fromIndex = Math.min(page * size, totalElements);
        int toIndex = Math.min(fromIndex + size, totalElements);

        List<StationDTO> pagedList = stations.subList(fromIndex, toIndex)
                .stream()
                .map(stationConverter::toDTO)
                .collect(Collectors.toList());

        PageDTO<StationDTO> pageDTO = new PageDTO<>();
        pageDTO.setContent(pagedList);
        pageDTO.setPageNumber(page);
        pageDTO.setPageSize(size);
        pageDTO.setTotalElements(totalElements);
        pageDTO.setTotalPages(totalPages);
        pageDTO.setFirst(page == 0);
        pageDTO.setLast(page + 1 >= totalPages);

        return new DataResponseMessage<>("Duraklar başarıyla listelendi.", true, pageDTO);
    }


    @Override
    public DataResponseMessage<StationDetailsDTO> getStationById(Long id, DirectionType directionType) {
        Station station = stationRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Durak bulunamadı."));

        List<Route> stationRoutes = routeService.findRoutesByStationId(id);
        List<RouteWithNextBusDTO> routeDtos = new ArrayList<>();

        for (Route route : stationRoutes) {
            List<Bus> activeBuses = routeService.findActiveBusesForRoute(route);

            List<NextBusDTO> nextBuses = new ArrayList<>();
            for (RouteDirection direction : route.getDirections()) {

                if (directionType != null && !direction.getType().equals(directionType)) {
                    continue;
                }

                List<Bus> directionBuses = activeBuses.stream()
                        .filter(bus -> bus.getCurrentDirection() != null &&
                                direction.getId().equals(bus.getCurrentDirection().getId()))
                        .toList();

                List<NextBusDTO> directionNextBuses = directionBuses.stream()
                        .map(bus -> calculateDetailedETA(bus, station, direction))
                        .filter(Objects::nonNull)
                        .filter(dto -> dto.getArrivalInMinutes() != null && dto.getArrivalInMinutes() < 60)
                        .sorted(Comparator.comparing(NextBusDTO::getArrivalInMinutes))
                        .limit(3)
                        .toList();

                nextBuses.addAll(directionNextBuses);
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

            routeDtos.add(dto);
        }

        StationDetailsDTO stationDto = stationConverter.toStationDetailsDto(station, routeDtos);
        return new DataResponseMessage<>("Durak bulundu.", true, stationDto);
    }


    public NextBusDTO calculateDetailedETA(Bus bus, Station targetStation, RouteDirection direction) {
        if (bus.getCurrentLatitude() == null || bus.getCurrentLongitude() == null ||
                targetStation.getLocation() == null) {
            return null;
        }

        try {
            double busLat = bus.getCurrentLatitude();
            double busLng = bus.getCurrentLongitude();
            double stationLat = targetStation.getLocation().getLatitude();
            double stationLng = targetStation.getLocation().getLongitude();

            RoutePosition busPosition = findBusPositionInRoute(bus, direction);
            if (busPosition == null) {
                return null;
            }

            RoutePosition targetPosition = findStationPositionInRoute(targetStation, direction);
            if (targetPosition == null) {
                return null;
            }

            if (busPosition.getSequenceOrder() >= targetPosition.getSequenceOrder()) {
                return null;
            }

            int remainingStops = targetPosition.getSequenceOrder() - busPosition.getSequenceOrder();

            Integer baseETAMinutes = googleMapsService.getEstimatedTimeInMinutes(
                    busLat, busLng, stationLat, stationLng
            );

            if (baseETAMinutes == null) {
                return null;
            }

            int stopWaitingTime = remainingStops * 1;

            double speedFactor = calculateSpeedFactor(bus);

            double trafficFactor = calculateTrafficFactor();

            int finalETA = (int) Math.round(
                    (baseETAMinutes * speedFactor * trafficFactor) + stopWaitingTime
            );

            return NextBusDTO.builder()
                    .plate(bus.getNumberPlate())
                    .arrivalInMinutes(finalETA)
                    .direction(direction.getType())
                    .directionName(direction.getName())
                    .currentLocation(getCurrentLocationDescription(bus, busPosition))
                    .remainingStops(remainingStops)
                    .occupancyRate((int) bus.getOccupancyRate())
                    .busStatus(bus.getStatus().getDisplayName())
                    .currentSpeed(bus.getLastKnownSpeed() != null ?
                            bus.getLastKnownSpeed().intValue() : null)
                    .trafficStatus(getTrafficStatus(trafficFactor))
                    .build();

        } catch (Exception e) {
            log.error("ETA hesaplama hatası - Bus: {}, Station: {}",
                    bus.getNumberPlate(), targetStation.getName(), e);
            return null;
        }
    }

    private RoutePosition findBusPositionInRoute(Bus bus, RouteDirection direction) {
        if (bus.getLastSeenStation() == null) {
            return null;
        }

        List<RouteStationNode> nodes = direction.getStationNodes();

        if (direction.getStartStation().getId().equals(bus.getLastSeenStation().getId())) {
            return new RoutePosition(0, direction.getStartStation());
        }

        for (int i = 0; i < nodes.size(); i++) {
            RouteStationNode node = nodes.get(i);
            if (node.getToStation().getId().equals(bus.getLastSeenStation().getId())) {
                return new RoutePosition(i + 1, node.getToStation());
            }
        }

        return null;
    }


    private RoutePosition findStationPositionInRoute(Station targetStation, RouteDirection direction) {
        if (direction.getStartStation().getId().equals(targetStation.getId())) {
            return new RoutePosition(0, direction.getStartStation());
        }

        List<RouteStationNode> nodes = direction.getStationNodes();
        for (int i = 0; i < nodes.size(); i++) {
            RouteStationNode node = nodes.get(i);
            if (node.getToStation().getId().equals(targetStation.getId())) {
                return new RoutePosition(i + 1, node.getToStation());
            }
        }

        return null;
    }


    private double calculateSpeedFactor(Bus bus) {
        if (bus.getLastKnownSpeed() == null) {
            return 1.0;
        }

        double speed = bus.getLastKnownSpeed();

        double averageCitySpeed = 25.0;

        if (speed < 10) {
            return 1.5;
        } else if (speed > 40) {
            return 0.8;
        } else {
            return speed / averageCitySpeed;
        }
    }


    private double calculateTrafficFactor() {
        LocalDateTime now = LocalDateTime.now();
        int hour = now.getHour();

        if ((hour >= 7 && hour <= 9) || (hour >= 17 && hour <= 19)) {
            return 1.4;
        } else if (hour >= 12 && hour <= 14) {
            return 1.2;
        } else if (hour >= 22 || hour <= 6) {
            return 0.8;
        } else {
            return 1.0;
        }
    }

    private String getCurrentLocationDescription(Bus bus, RoutePosition position) {
        if (bus.getLastSeenStation() != null) {
            return bus.getLastSeenStation().getName() + " civarında";
        } else if (position != null && position.getStation() != null) {
            return position.getStation().getName() + " yakınında";
        } else {
            return "Konum belirleniyor";
        }
    }


    private String getTrafficStatus(double trafficFactor) {
        if (trafficFactor >= 1.4) {
            return "Yoğun Trafik";
        } else if (trafficFactor >= 1.2) {
            return "Orta Trafik";
        } else if (trafficFactor <= 0.8) {
            return "Hafif Trafik";
        } else {
            return "Normal Trafik";
        }
    }


    @Override
    public DataResponseMessage<PageDTO<StationDTO>> searchStationsByName(String name, int page, int size) {
        String query = name != null ? name.toLowerCase() : "";

        List<Station> stations = stationRepository.findAll().stream()
                .filter(station -> station.isActive() && !station.isDeleted())
                .filter(station -> {
                    String stationName = station.getName() != null ? station.getName().toLowerCase() : "";
                    String street = station.getAddress() != null && station.getAddress().getStreet() != null
                            ? station.getAddress().getStreet().toLowerCase() : "";
                    String district = station.getAddress() != null && station.getAddress().getDistrict() != null
                            ? station.getAddress().getDistrict().toLowerCase() : "";
                    String city = station.getAddress() != null && station.getAddress().getCity() != null
                            ? station.getAddress().getCity().toLowerCase() : "";

                    return stationName.contains(query) || street.contains(query) || district.contains(query) || city.contains(query);
                })
                .toList();

        int total = stations.size();
        int totalPages = (int) Math.ceil((double) total / size);
        int fromIndex = Math.min(page * size, total);
        int toIndex = Math.min(fromIndex + size, total);

        List<StationDTO> content = stations.subList(fromIndex, toIndex)
                .stream()
                .map(stationConverter::toDTO)
                .collect(Collectors.toList());

        PageDTO<StationDTO> pageDTO = new PageDTO<>();
        pageDTO.setContent(content);
        pageDTO.setPageNumber(page);
        pageDTO.setPageSize(size);
        pageDTO.setTotalElements(total);
        pageDTO.setTotalPages(totalPages);
        pageDTO.setFirst(page == 0);
        pageDTO.setLast(page + 1 >= totalPages);

        return new DataResponseMessage<>("İstasyon arama sonuçları başarıyla listelendi.", true, pageDTO);
    }


    @Override
    public DataResponseMessage<PageDTO<StationDTO>> searchNearbyStations(SearchStationRequest request, int page, int size) {
        double radiusKm = 5.0;
        double lat = request.getLatitude();
        double lon = request.getLongitude();
        String query = request.getQuery() != null ? request.getQuery().toLowerCase() : "";

        List<Station> allStations = stationRepository.findAll();

        List<Station> matchedStations = allStations.stream()
                .filter(station -> station.isActive() && !station.isDeleted())
                .filter(station -> {
                    String name = station.getName() != null ? station.getName().toLowerCase() : "";
                    String street = station.getAddress().getStreet() != null ? station.getAddress().getStreet().toLowerCase() : "";
                    String district = station.getAddress().getDistrict() != null ? station.getAddress().getDistrict().toLowerCase() : "";
                    String city = station.getAddress().getCity() != null ? station.getAddress().getCity().toLowerCase() : "";

                    return name.contains(query) ||
                            street.contains(query) ||
                            district.contains(query) ||
                            city.contains(query);
                })
                .toList();

        if (matchedStations.isEmpty() && lat != 0 && lon != 0) {
            matchedStations = allStations.stream()
                    .filter(station -> station.isActive() && !station.isDeleted())
                    .filter(station -> {
                        double stationLat = station.getLocation().getLatitude();
                        double stationLon = station.getLocation().getLongitude();
                        return haversine(lat, lon, stationLat, stationLon) <= radiusKm;
                    })
                    .toList();
        }

        // Sayfalama
        int total = matchedStations.size();
        int totalPages = (int) Math.ceil((double) total / size);
        int fromIndex = Math.min(page * size, total);
        int toIndex = Math.min(fromIndex + size, total);

        List<StationDTO> content = matchedStations.subList(fromIndex, toIndex)
                .stream()
                .map(stationConverter::toDTO)
                .toList();

        PageDTO<StationDTO> pageDTO = new PageDTO<>();
        pageDTO.setContent(content);
        pageDTO.setPageNumber(page);
        pageDTO.setPageSize(size);
        pageDTO.setTotalElements(total);
        pageDTO.setTotalPages(totalPages);
        pageDTO.setFirst(page == 0);
        pageDTO.setLast(page + 1 >= totalPages);

        return new DataResponseMessage<>("İstasyonlar başarıyla listelendi.", true, pageDTO);
    }

    @Override
    public DataResponseMessage<List<StationDTO>> getFavorite(String username) {
        User user = userRepository.findByUserNumber(username).orElseThrow(EntityNotFoundException::new);
        return new DataResponseMessage<>("favoriler", true, user.getFavoriteStations().stream().map(stationConverter::toDTO).collect(Collectors.toList()));
    }

    @Override
    @Transactional
    public ResponseMessage removeFavoriteStation(String username, Long stationId) {
        User user = userRepository.findByUserNumber(username).orElseThrow(EntityNotFoundException::new);
        boolean isDeleted = user.getFavoriteStations().removeIf(station -> station.getId().equals(stationId));
        return new ResponseMessage("silme işlemi :" + isDeleted, true);
    }

    @Override
    @Transactional
    public ResponseMessage addFavoriteStation(String username, Long stationId) throws StationNotFoundException, StationNotActiveException {
        User user = userRepository.findByUserNumber(username).orElseThrow(EntityNotFoundException::new);
        if (user.getFavoriteStations().isEmpty()) {
            List<Station> stations = new ArrayList<>();
            user.setFavoriteStations(stations);
        }
        if ((long) user.getFavoriteStations().size() > 10) {
            return new ResponseMessage("Daha fazla durak favorilere eklenemez", false);
        }
        Station station = stationRepository.findById(stationId).orElseThrow(StationNotFoundException::new);
        if (!station.isActive() || station.isDeleted()) {
            throw new StationNotActiveException();
        }
        user.getFavoriteStations().add(station);
        userRepository.save(user);

        return new ResponseMessage("Durak favorilere eklendi.", true);
    }

    @Override
    public Set<String> getMatchingKeywords(String query) {
        String lowerQuery = query.toLowerCase();

        return stationRepository.findAll().stream()
                .filter(station -> station.isActive() && !station.isDeleted())
                .flatMap(station -> {
                    Set<String> keywords = new HashSet<>();

                    if (station.getName() != null) {
                        keywords.addAll(splitWords(station.getName()));
                    }

                    if (station.getAddress() != null) {
                        if (station.getAddress().getStreet() != null)
                            keywords.addAll(splitWords(station.getAddress().getStreet()));
                        if (station.getAddress().getDistrict() != null)
                            keywords.addAll(splitWords(station.getAddress().getDistrict()));
                        if (station.getAddress().getCity() != null)
                            keywords.addAll(splitWords(station.getAddress().getCity()));
                    }

                    return keywords.stream();
                })
                .filter(word -> word.toLowerCase().contains(lowerQuery))
                .collect(Collectors.toSet());
    }

    @Override
    public DataResponseMessage<List<PublicRouteDTO>> getRoutes(Long stationId) throws StationNotFoundException {
        Station station = stationRepository.findById(stationId)
                .orElseThrow(StationNotFoundException::new);

        List<Route> allRoutes = routeRepository.findAll();

        List<Route> matchedRoutes = allRoutes.stream()
                .filter(route -> route.isActive() && !route.isDeleted())
                .filter(route -> route.getDirections().stream()
                        .flatMap(direction -> direction.getStationNodes().stream())
                        .anyMatch(node ->
                                node.getFromStation().getId().equals(stationId) ||
                                        node.getToStation().getId().equals(stationId))
                )
                .toList();

        List<PublicRouteDTO> result = matchedRoutes.stream()
                .map(routeConverter::toPublicRoute)
                .toList();

        return new DataResponseMessage<>(" İstasyona ait rotalar başarıyla listelendi.", true, result);
    }


    @Override
    public DataResponseMessage<PageDTO<StationDTO>> NearbyStations(double userLat, double userLon, int page, int size) {
        double radiusKm = 5.0;

        List<Station> nearbyStations = stationRepository.findAll().stream()
                .filter(station -> station.isActive() && !station.isDeleted())
                .filter(station -> {
                    double stationLat = station.getLocation().getLatitude();
                    double stationLon = station.getLocation().getLongitude();
                    double distance = haversine(userLat, userLon, stationLat, stationLon);
                    return distance <= radiusKm;
                })
                .sorted(Comparator.comparingDouble(station ->
                        haversine(userLat, userLon,
                                station.getLocation().getLatitude(),
                                station.getLocation().getLongitude())))
                .toList();

        int totalElements = nearbyStations.size();
        int totalPages = (int) Math.ceil((double) totalElements / size);
        int fromIndex = page * size;
        int toIndex = Math.min(fromIndex + size, totalElements);

        List<StationDTO> pagedStations = nearbyStations.subList(fromIndex, toIndex)
                .stream()
                .map(stationConverter::toDTO)
                .toList();

        PageDTO<StationDTO> pageDTO = new PageDTO<>();
        pageDTO.setContent(pagedStations);
        pageDTO.setPageNumber(page);
        pageDTO.setPageSize(size);
        pageDTO.setTotalElements(totalElements);
        pageDTO.setTotalPages(totalPages);
        pageDTO.setFirst(page == 0);
        pageDTO.setLast(page + 1 >= totalPages);

        return new DataResponseMessage<>("Yakındaki duraklar başarıyla listelendi.", true, pageDTO);
    }


    private Set<String> splitWords(String text) {
        if (text == null) return Set.of();

        String[] parts = text.split("[\\s,.:;-]+");

        return Arrays.stream(parts)
                .filter(part -> !part.isBlank())
                .collect(Collectors.toSet());
    }


    private double haversine(double lat1, double lon1, double lat2, double lon2) {
        final int R = 6371; // Dünya yarıçapı km
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
                        Math.sin(dLon / 2) * Math.sin(dLon / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }


    // Helper methods

    private boolean isAdminOrSuperAdmin(UserDetails userDetails) {
        return userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ADMIN") || auth.getAuthority().equals("SUPERADMIN"));
    }


    private double distance(double lat1, double lon1, double lat2, double lon2) {
        final int R = 6371;
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a =
                Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                        Math.cos(Math.toRadians(lat1)) *
                                Math.cos(Math.toRadians(lat2)) *
                                Math.sin(dLon / 2) *
                                Math.sin(dLon / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }
}
