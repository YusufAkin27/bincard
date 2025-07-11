package akin.city_card.bus.service.concretes;

import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.bus.core.converter.BusConverter;
import akin.city_card.bus.core.request.CreateBusRequest;
import akin.city_card.bus.core.request.UpdateBusRequest;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.BusRideDTO;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.bus.exceptions.*;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusLocation;
import akin.city_card.bus.model.BusRide;
import akin.city_card.bus.model.RideStatus;
import akin.city_card.bus.repository.BusLocationRepository;
import akin.city_card.bus.repository.BusRepository;
import akin.city_card.bus.repository.BusRideRepository;
import akin.city_card.bus.service.abstracts.BusService;
import akin.city_card.buscard.model.BusCard;
import akin.city_card.buscard.model.CardType;
import akin.city_card.buscard.repository.BusCardRepository;
import akin.city_card.driver.model.Driver;
import akin.city_card.driver.repository.DriverRepository;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.model.Route;
import akin.city_card.route.repository.RouteRepository;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class BusManager implements BusService {
    private final BusConverter busConverter;
    private final AdminRepository adminRepository;
    private final SuperAdminRepository superAdminRepository;
    private final RouteRepository routeRepository;
    private final DriverRepository driverRepository;
    private final BusRepository busRepository;
    private final UserRepository userRepository;
    private final BusLocationRepository busLocationRepository;
    private  final BusCardRepository busCardRepository;
    private final BusRideRepository   busRideRepository;


    @Override
    public DataResponseMessage<List<BusDTO>> getAllBuses(String username) throws AdminNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (admin == null && superAdmin == null) {
            throw new AdminNotFoundException();
        }
        List<Bus> buses = new ArrayList<>();
        return new DataResponseMessage<>("başarılı", true, buses.stream().map(busConverter::toBusDTO).collect(Collectors.toList()));
    }

    @Override
    public DataResponseMessage<BusDTO> getBusById(Long busId, String username) throws AdminNotFoundException, BusNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (admin == null && superAdmin == null) {
            throw new AdminNotFoundException();
        }
        Bus bus = busRepository.findById(busId).orElseThrow(() -> new BusNotFoundException(busId));
        BusDTO busDTO = busConverter.toBusDTO(bus);

        return new DataResponseMessage<>("otobüs", true, busDTO);
    }

    @Override
    public DataResponseMessage<List<BusDTO>> getActiveBuses(String username) {
        return null;
    }

    @Override
    public ResponseMessage createBus(CreateBusRequest request, String username) throws AdminNotFoundException, DuplicateBusPlateException, RouteNotFoundException, DriverNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (admin == null && superAdmin == null) {
            throw new AdminNotFoundException();
        }

        if (busRepository.existsByNumberPlate(request.getNumberPlate())) {
            throw new DuplicateBusPlateException();
        }

        Bus bus = busConverter.fromCreateBusRequest(request);

        Route route = routeRepository.findById(request.getRouteId())
                .orElseThrow(() -> new RouteNotFoundException(request.getRouteId()));
        bus.setRoute(route);

        Driver driver = driverRepository.findById(request.getDriverId())
                .orElseThrow(() -> new DriverNotFoundException(request.getDriverId()));
        bus.setDriver(driver);

        busRepository.save(bus);

        return new ResponseMessage("Otobüs başarıyla oluşturuldu.", true);
    }


    @Override
    public ResponseMessage updateBus(Long busId, UpdateBusRequest request, String username) throws AdminNotFoundException, DuplicateBusPlateException, DriverNotFoundException, RouteNotFoundException, BusNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (admin == null && superAdmin == null) {
            throw new AdminNotFoundException();
        }

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        if (!bus.getNumberPlate().equals(request.getNumberPlate()) &&
                busRepository.existsByNumberPlate(request.getNumberPlate())) {
            throw new DuplicateBusPlateException();
        }

        busConverter.updateBusFromRequest(bus, request);

        if (request.getDriverId() != null) {
            Driver driver = driverRepository.findById(request.getDriverId())
                    .orElseThrow(() -> new DriverNotFoundException(request.getDriverId()));
            bus.setDriver(driver);
        }

        if (request.getRouteId() != null) {
            Route route = routeRepository.findById(request.getRouteId())
                    .orElseThrow(() -> new RouteNotFoundException(request.getRouteId()));
            bus.setRoute(route);
        }

        busRepository.save(bus);
        return new ResponseMessage("Otobüs başarıyla güncellendi.", true);
    }


    @Override
    public ResponseMessage deleteBus(Long busId, String username) throws AdminNotFoundException, BusNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (admin == null && superAdmin == null) {
            throw new AdminNotFoundException();
        }

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        if (!bus.isActive()) {
            return new ResponseMessage("Otobüs zaten pasif durumda.", false);
        }

        bus.setActive(false);
        busRepository.save(bus);

        return new ResponseMessage("Otobüs başarıyla pasif hale getirildi.", true);
    }


    @Override
    public ResponseMessage toggleBusActive(Long busId, String username) throws AdminNotFoundException, BusNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (admin == null && superAdmin == null) {
            throw new AdminNotFoundException();
        }

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        if (bus.isActive()) {
            return new ResponseMessage("Otobüs zaten aktif durumda.", false);
        }

        bus.setActive(true);
        busRepository.save(bus);

        return new ResponseMessage("Otobüs başarıyla aktif hale getirildi.", true);
    }

    @Override
    public ResponseMessage assignDriver(Long busId, Long driverId, String username) throws AdminNotFoundException, BusNotFoundException, DriverNotFoundException, DriverAlreadyAssignedException {
        Admin admin = adminRepository.findByUserNumber(username);
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (admin == null && superAdmin == null) {
            throw new AdminNotFoundException();
        }

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        Driver driver = driverRepository.findById(driverId)
                .orElseThrow(() -> new DriverNotFoundException(driverId));

        if (driver.getAssignedBus() != null && !driver.getAssignedBus().getId().equals(busId)) {
            throw new DriverAlreadyAssignedException(driverId);
        }

        bus.setDriver(driver);
        busRepository.save(bus);

        return new ResponseMessage("Şoför başarıyla otobüse atandı.", true);
    }


    @Override
    public DataResponseMessage<BusLocationDTO> getCurrentLocation(Long busId, String username) throws UserNotFoundException, BusNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);


        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        BusLocation currentLocation = busLocationRepository.findTopByBusOrderByTimestampDesc(bus)
                .orElse(null);

        if (currentLocation == null) {
            return new DataResponseMessage<>("Otobüs için konum bilgisi bulunamadı.", false, null);
        }

        BusLocationDTO dto = busConverter.toBusLocationDTO(currentLocation);

        return new DataResponseMessage<>("Otobüsün güncel konumu getirildi.", true, dto);
    }


    @Override
    public ResponseMessage updateLocation(Long busId, UpdateLocationRequest request) throws UnauthorizedLocationUpdateException, BusNotFoundException {
        String requestIp = RequestContextHolder.currentRequestAttributes()
                .getAttribute("CLIENT_IP", RequestAttributes.SCOPE_REQUEST)
                .toString();

        List<String> allowedIps = List.of("192.168.1.10", "192.168.1.11"); // örnek IP’ler
        if (!allowedIps.contains(requestIp)) {
            throw new UnauthorizedLocationUpdateException(requestIp);
        }

        if (request.getLatitude() == null || request.getLongitude() == null
                || request.getLatitude() < -90 || request.getLatitude() > 90
                || request.getLongitude() < -180 || request.getLongitude() > 180) {
            return new ResponseMessage("Geçersiz konum bilgisi.", false);
        }

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        BusLocation location = new BusLocation();
        location.setBus(bus);
        location.setLatitude(request.getLatitude());
        location.setLongitude(request.getLongitude());
        location.setTimestamp(LocalDateTime.now());

        busLocationRepository.save(location);

        bus.setCurrentLatitude(request.getLatitude());
        bus.setCurrentLongitude(request.getLongitude());
        bus.setLastLocationUpdate(LocalDateTime.now());
        busRepository.save(bus);

        return new ResponseMessage("Otobüs konumu başarıyla güncellendi.", false);
    }


    @Override
    public DataResponseMessage<List<BusLocationDTO>> getLocationHistory(Long busId, LocalDate date, String username) throws UnauthorizedAccessException, BusNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (admin == null && superAdmin == null) {
            throw new UnauthorizedAccessException();
        }

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        List<BusLocation> locations;

        if (date != null) {
            LocalDateTime startOfDay = date.atStartOfDay();
            LocalDateTime endOfDay = date.plusDays(1).atStartOfDay();

            locations = busLocationRepository.findAllByBusAndTimestampBetweenOrderByTimestampDesc(
                    bus, startOfDay, endOfDay
            );
        } else {
            locations = busLocationRepository.findAllByBusOrderByTimestampDesc(bus);
        }

        List<BusLocationDTO> dtos = locations.stream()
                .map(busConverter::toBusLocationDTO)
                .toList();

        return new DataResponseMessage<>( "Konum geçmişi başarıyla getirildi.", true,dtos);
    }


    @Override
    @Transactional
    public ResponseMessage rideWithCard(Long busId, Long cardId, CardType cardType, String username) throws BusNotFoundException, CardNotFoundException, UnauthorizedCardUsageException, InsufficientBalanceException {
        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        BusCard card = busCardRepository.findById(cardId)
                .orElseThrow(() -> new CardNotFoundException(cardId));

        if (!card.isActive() || !card.getUser().getUserNumber().equals(username)) {
            throw new UnauthorizedCardUsageException();
        }
        double fare = bus.calculateFare(cardType);

        LocalDateTime now = LocalDateTime.now();
        BusRide lastRide = busRideRepository.findTopByBusCardOrderByBoardingTimeDesc(card);

        boolean isTransfer = false;
        if (lastRide != null) {
            long minutes = Duration.between(lastRide.getBoardingTime(), now).toMinutes();

            boolean sameStation = lastRide.getBus().getRoute().getStations().get(0)
                    .equals(bus.getRoute().getStations().get(0));

            if (minutes <= 60 && !sameStation) {
                isTransfer = true;
                fare = 0.0;
            }
        }

        // 6. Bakiye kontrolü
        if (card.getBalance().compareTo(BigDecimal.valueOf(fare)) < 0) {
            throw new InsufficientBalanceException();
        }

        // 7. Bakiyeyi düş
        card.setBalance(card.getBalance().subtract(BigDecimal.valueOf(fare)));
        busCardRepository.save(card);



        // 8. Yeni biniş kaydı oluştur
        BusRide ride = new BusRide();
        ride.setBus(bus);
        ride.setBusCard(card);
        ride.setBoardingTime(now);
        ride.setFareCharged(BigDecimal.valueOf(fare));
        ride.setStatus(RideStatus.SUCCESS);
        busRideRepository.save(ride);

        return new ResponseMessage( isTransfer ? "Aktarma ile biniş başarılı." : "Biniş başarılı.",true);
    }

    @Override
    public DataResponseMessage<List<BusRideDTO>> getBusRides(Long busId, String username) {
       /*
        Bus bus = busRepository.findById(busId).orElseThrow(BusNotFoundException::new);

        // İstersen burada username ile yetki kontrolü yapabilirsin (örneğin admin veya bus yetkilisi mi)

        List<BusRide> rides = busRideRepository.findByBusId(busId);
        List<BusRideDTO> rideDTOs = rides.stream()
                .map(busConverter::toBusRideDTO)
                .toList();

        return DataResponseMessage.<List<BusRideDTO>>builder()
                .data(rideDTOs)
                .build();

        */
        return null;
    }

    @Override
    public ResponseMessage assignRoute(Long busId, Long routeId, String username) {
        Bus bus = busRepository.findById(busId).orElseThrow();
        Route route = routeRepository.findById(routeId).orElseThrow();


        bus.setRoute(route);
        busRepository.save(bus);

        return new ResponseMessage("Route assigned to bus successfully", true);
    }

    @Override
    public DataResponseMessage<List<StationDTO>> getRouteStations(Long busId, String username) {
        /*
        Bus bus = busRepository.findById(busId).orElseThrow();

        Route route = bus.getRoute();
        if (route == null) {
            return DataResponseMessage.<List<StationDTO>>builder()
                    .build();
        }

        List<Station> stations = stationRepository.findByRouteIdOrderByOrderAsc(route.getId());
        List<StationDTO> stationDTOs = stations.stream()
                .map(stationConverter::toStationDTO)
                .toList();

        return DataResponseMessage.<List<StationDTO>>builder()
                .data(stationDTOs)
                .build();


         */
        return null;
    }

    @Override
    public DataResponseMessage<Double> getEstimatedArrivalTime(Long busId, Long stationId, String username) {

        /*
        Bus bus = busRepository.findById(busId).orElseThrow(BusNotFoundException::new);
        Station station = stationRepository.findById(stationId).orElseThrow(StationNotFoundException::new);

        Route route = bus.getRoute();
        if (route == null) {
            return DataResponseMessage.<Double>builder()
                    .success(false)
                    .message("No route assigned to bus")
                    .build();
        }


        double eta = busLocationService.calculateEstimatedArrivalTime(bus, station);

        return DataResponseMessage.<Double>builder()
                .success(true)
                .data(eta)
                .message("Estimated arrival time calculated successfully")
                .build();

         */
        return null;
    }

}
