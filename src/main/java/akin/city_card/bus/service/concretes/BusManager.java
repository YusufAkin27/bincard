package akin.city_card.bus.service.concretes;

import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.bus.core.converter.BusConverter;
import akin.city_card.bus.core.request.BusStatusUpdateRequest;
import akin.city_card.bus.core.request.CreateBusRequest;
import akin.city_card.bus.core.request.UpdateBusRequest;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.CurrentStationInfoDTO;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.bus.exceptions.*;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusLocation;
import akin.city_card.bus.model.BusStatus;
import akin.city_card.bus.repository.BusLocationRepository;
import akin.city_card.bus.repository.BusRepository;
import akin.city_card.bus.service.abstracts.BusService;
import akin.city_card.bus.service.abstracts.GoogleMapsService;
import akin.city_card.driver.model.Driver;
import akin.city_card.driver.repository.DriverRepository;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.exceptions.RouteNotActiveException;
import akin.city_card.route.model.Route;
import akin.city_card.route.model.RouteDirection;
import akin.city_card.route.model.RouteStationNode;
import akin.city_card.route.repository.RouteDirectionRepository;
import akin.city_card.route.repository.RouteRepository;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.station.core.converter.StationConverter;
import akin.city_card.station.exceptions.StationNotActiveException;
import akin.city_card.station.exceptions.StationNotFoundException;
import akin.city_card.station.model.Station;
import akin.city_card.station.repository.StationRepository;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class BusManager implements BusService {

    private final BusConverter busConverter;
    private final AdminRepository adminRepository;
    private final SuperAdminRepository superAdminRepository;
    private final RouteRepository routeRepository;
    private final DriverRepository driverRepository;
    private final BusRepository busRepository;
    private final BusLocationRepository busLocationRepository;
    private final StationRepository stationRepository;
    private final GoogleMapsService googleMapsService;
    private final StationConverter stationConverter;
    private final RouteDirectionRepository routeDirectionRepository;


    private SecurityUser getAdminOrSuperAdmin(String username) throws AdminNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin != null) {
            return admin; // Admin extends SecurityUser
        }

        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (superAdmin != null) {
            return superAdmin; // SuperAdmin extends SecurityUser
        }

        throw new AdminNotFoundException();
    }


    @Override
    public DataResponseMessage<PageDTO<BusDTO>> getAllBuses(int page, int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        Page<Bus> busPage = busRepository.findAll(pageable);

        List<BusDTO> busDTOs = busConverter.toBusDTOList(busPage.getContent());

        PageDTO<BusDTO> pageDTO = new PageDTO<>();
        pageDTO.setContent(busDTOs);
        pageDTO.setPageNumber(busPage.getNumber());
        pageDTO.setPageSize(busPage.getSize());
        pageDTO.setTotalElements(busPage.getTotalElements());
        pageDTO.setTotalPages(busPage.getTotalPages());
        pageDTO.setLast(busPage.isLast());

        return new DataResponseMessage<>("Tüm otobüsler başarıyla getirildi.", true, pageDTO);
    }

    @Override
    public DataResponseMessage<BusDTO> getBusById(Long busId, String username) throws BusNotFoundException {

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));
        BusDTO busDTO = busConverter.toBusDTO(bus);

        return new DataResponseMessage<>("Otobüs başarıyla getirildi.", true, busDTO);
    }

    @Override
    public DataResponseMessage<PageDTO<BusDTO>> getActiveBuses(String username, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        Page<Bus> busPage = busRepository.findAllByIsActiveTrueAndIsDeletedFalse(pageable);
        Page<BusDTO> busDTOPage = busPage.map(busConverter::toBusDTO);

        PageDTO<BusDTO> pageDTO = new PageDTO<>();
        pageDTO.setContent(busDTOPage.getContent());
        pageDTO.setPageNumber(busPage.getNumber());
        pageDTO.setPageSize(busPage.getSize());
        pageDTO.setTotalElements(busPage.getTotalElements());
        pageDTO.setTotalPages(busPage.getTotalPages());
        pageDTO.setLast(busPage.isLast());

        return new DataResponseMessage<>("Aktif otobüsler başarıyla getirildi.", true, pageDTO);
    }


    @Override
    @Transactional
    public ResponseMessage createBus(CreateBusRequest request, String username)
            throws DuplicateBusPlateException,
            RouteNotFoundException, DriverNotFoundException, DriverInactiveException,
            DriverAlreadyAssignedToBusException, BusAlreadyAssignedAnotherDriverException, RouteNotActiveException, AdminNotFoundException {

        SecurityUser securityUser = getAdminOrSuperAdmin(username);

        String plateNumber = request.getNumberPlate().trim().toUpperCase();
        if (busRepository.existsByNumberPlateAndIsDeletedFalse(plateNumber)) {
            throw new DuplicateBusPlateException();
        }

        Bus bus = busConverter.fromCreateBusRequest(request);

        if (request.getRouteId() != null) {
            Route route = routeRepository.findById(request.getRouteId())
                    .orElseThrow(RouteNotFoundException::new);
            if (!route.isActive() || route.isDeleted()) throw new RouteNotActiveException();

            bus.setAssignedRoute(route);

            if (route.getOutgoingDirection() != null) {
                bus.setCurrentDirection(route.getOutgoingDirection());
            }
        }

        if (request.getDriverId() != null) {
            Driver driver = driverRepository.findById(request.getDriverId())
                    .orElseThrow(() -> new DriverNotFoundException());

            if (!driver.getActive()) {
                throw new DriverInactiveException(driver.getId());
            }

            if (busRepository.existsByDriverIdAndIsActiveTrueAndIsDeletedFalse(driver.getId())) {
                throw new DriverAlreadyAssignedToBusException(driver.getId());
            }

            if (bus.getDriver() != null && !bus.getDriver().getId().equals(driver.getId())) {
                throw new BusAlreadyAssignedAnotherDriverException(bus.getNumberPlate());
            }

            bus.setDriver(driver);
        }

        bus.setStatus(BusStatus.CALISIYOR);
        bus.setCreatedBy(securityUser);
        bus.setUpdatedBy(securityUser);

        busRepository.save(bus);
        log.info("Otobüs oluşturuldu {}", plateNumber);

        return new ResponseMessage("Otobüs başarıyla oluşturuldu.", true);
    }


    @Override
    @Transactional
    public ResponseMessage updateBus(Long busId, UpdateBusRequest request, String username)
            throws DuplicateBusPlateException,
            DriverNotFoundException, RouteNotFoundException, BusNotFoundException, UserNotFoundException, DriverAlreadyAssignedToBusException, RouteDirectionNotFoundException, AdminNotFoundException {

        SecurityUser securityUser = getAdminOrSuperAdmin(username);

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        if (request.getNumberPlate() != null && !request.getNumberPlate().trim().isEmpty()) {
            String newPlate = request.getNumberPlate().trim().toUpperCase();
            if (!bus.getNumberPlate().equals(newPlate) &&
                    busRepository.existsByNumberPlateAndIsDeletedFalse(newPlate)) {
                throw new DuplicateBusPlateException();
            }
        }

        if (request.getDriverId() != null) {
            Driver newDriver = driverRepository.findById(request.getDriverId())
                    .orElseThrow(DriverNotFoundException::new);

            Optional<Bus> existingBusWithDriver = busRepository.findByDriverIdAndIsActiveTrueAndIsDeletedFalse(newDriver.getId());
            if (existingBusWithDriver.isPresent() && !existingBusWithDriver.get().getId().equals(busId)) {
                throw new DriverAlreadyAssignedToBusException(request.getDriverId());
            }

            bus.setDriver(newDriver);
        }

        if (request.getRouteId() != null) {
            Route route = routeRepository.findById(request.getRouteId())
                    .orElseThrow(RouteNotFoundException::new);
            bus.setAssignedRoute(route);

            if (request.getCurrentDirectionId() != null) {
                RouteDirection direction = routeDirectionRepository.findById(request.getCurrentDirectionId()).orElseThrow(RouteDirectionNotFoundException::new);
                bus.setCurrentDirection(direction);
            }
        }

        busConverter.updateBusFromRequest(bus, request);
        bus.setUpdatedBy(securityUser);

        busRepository.save(bus);
        log.info("Otobüs güncellendi {}", bus.getNumberPlate());

        return new ResponseMessage("Otobüs başarıyla güncellendi.", true);
    }

    @Override
    @Transactional
    public ResponseMessage deleteBus(Long busId, String username)
            throws AdminNotFoundException, BusNotFoundException, UserNotFoundException, BusAlreadyIsDeletedException {

        SecurityUser securityUser = getAdminOrSuperAdmin(username);

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));
        if (bus.isDeleted()) {
            throw new BusAlreadyIsDeletedException();
        }

        bus.setDeleted(true);
        bus.setDeletedAt(LocalDateTime.now());
        bus.setDeletedBy(securityUser);
        bus.setActive(false);
        bus.setStatus(BusStatus.SERVIS_DISI);

        if (bus.getDriver() != null) {
            bus.setDriver(null);
        }

        busRepository.save(bus);
        log.info("Otobüs silindi {}", bus.getNumberPlate());

        return new ResponseMessage("Otobüs başarıyla silindi.", true);
    }


    @Override
    @Transactional
    public ResponseMessage toggleBusActive(Long busId, String username)
            throws AdminNotFoundException, BusNotFoundException {

        SecurityUser securityUser = getAdminOrSuperAdmin(username);

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        boolean newActiveStatus = !bus.isActive();
        bus.setActive(newActiveStatus);

        if (newActiveStatus) {
            bus.setStatus(BusStatus.CALISIYOR);
        } else {
            bus.setStatus(BusStatus.SERVIS_DISI);
        }

        bus.setUpdatedBy(securityUser);
        busRepository.save(bus);

        String message = newActiveStatus ?
                "Otobüs başarıyla aktif hale getirildi." :
                "Otobüs başarıyla pasif hale getirildi.";

        log.info("Bus active status changed: {} - {}", bus.getNumberPlate(), newActiveStatus);
        return new ResponseMessage(message, true);
    }




    @Override
    public DataResponseMessage<BusLocationDTO> getCurrentLocation(Long busId, String username) throws BusNotFoundException, AdminNotFoundException, BusLocationNotFoundException {
        SecurityUser securityUser = getAdminOrSuperAdmin(username);

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));


        BusLocation currentLocation = busLocationRepository.findTopByBusOrderByTimestampDesc(bus)
                .orElse(null);

        if (currentLocation == null) {
            throw new BusLocationNotFoundException();
        }

        BusLocationDTO dto = busConverter.toBusLocationDTO(currentLocation);
        return new DataResponseMessage<>("Otobüsün güncel konumu getirildi.", true, dto);
    }

    @Override
    @Transactional
    public ResponseMessage updateLocation(Long busId, UpdateLocationRequest request) throws BusNotFoundException {

        Bus bus = busRepository.findByIdAndIsDeletedFalse(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        BusLocation location = busConverter.fromUpdateLocationRequest(request);
        location.setBus(bus);

        try {
            Station closestStation = findClosestStation(request.getLatitude(), request.getLongitude());
            if (closestStation != null) {
                location.setClosestStation(closestStation);
            }
        } catch (Exception e) {
            log.warn("Could not find closest station for bus {}: {}", busId, e.getMessage());
        }

        busLocationRepository.save(location);

        bus.setCurrentLatitude(request.getLatitude());
        bus.setCurrentLongitude(request.getLongitude());
        bus.setLastLocationUpdate(LocalDateTime.now());

        if (request.getSpeed() != null) {
            bus.setLastKnownSpeed(request.getSpeed());
        }

        // Otobüsün rotasındaki en yakın durağı bul ve güncelle
        try {
            updateBusStationInfo(bus, request.getLatitude(), request.getLongitude());
        } catch (Exception e) {
            log.warn("Could not update bus station info for bus {}: {}", busId, e.getMessage());
        }

        busRepository.save(bus);

        log.debug("Location updated for bus {}: {}, {}", busId, request.getLatitude(), request.getLongitude());
        return new ResponseMessage("Otobüs konumu başarıyla güncellendi.", true);
    }

    @Override
    public DataResponseMessage<PageDTO<BusLocationDTO>> getLocationHistory(
            Long busId,
            LocalDate date,
            String username,
            int page,
            int size
    ) throws UnauthorizedAccessException, BusNotFoundException, AdminNotFoundException {

        SecurityUser securityUser = getAdminOrSuperAdmin(username);

        Bus bus = busRepository.findByIdAndIsDeletedFalse(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        LocalDateTime start, end;
        if (date != null) {
            start = date.atStartOfDay();
            end = date.plusDays(1).atStartOfDay();
        } else {
            start = LocalDateTime.now().minusDays(1);
            end = LocalDateTime.now();
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());
        Page<BusLocation> locationPage = busLocationRepository
                .findAllByBusAndTimestampBetween(bus, start, end, pageable);

        PageDTO<BusLocationDTO> pageDTO = busConverter.toLocationPageDTO(locationPage);

        return new DataResponseMessage<>("Konum geçmişi başarıyla getirildi.", true, pageDTO);
    }


    @Override
    @Transactional
    public ResponseMessage assignRoute(Long busId, Long routeId, String username) {
        try {
            SecurityUser securityUser = getAdminOrSuperAdmin(username);

            Bus bus = busRepository.findById(busId)
                    .orElseThrow(() -> new BusNotFoundException(busId));

            if (!bus.isActive() || bus.isDeleted()) throw new BusInactiveException(busId);
            Route route = routeRepository.findById(routeId)
                    .orElseThrow(RouteNotFoundException::new);

            if (!route.isActive() || route.isDeleted()) throw new RouteNotActiveException();

            bus.setAssignedRoute(route);

            if (route.getOutgoingDirection() != null) {
                bus.setCurrentDirection(route.getOutgoingDirection());
            }

            bus.setUpdatedBy(securityUser);
            busRepository.save(bus);

            log.info("Route assigned to bus: {} -> {}", route.getName(), bus.getNumberPlate());
            return new ResponseMessage("Rota başarıyla otobüse atandı.", true);
        } catch (Exception e) {
            log.error("Error assigning route to bus: ", e);
            return new ResponseMessage("Rota ataması sırasında hata oluştu.", false);
        }
    }

    @Override
    public DataResponseMessage<List<StationDTO>> getRouteStations(Long busId, String username) {
        try {
            Bus bus = busRepository.findByIdAndIsDeletedFalse(busId)
                    .orElseThrow(() -> new BusNotFoundException(busId));

            Route route = bus.getAssignedRoute();
            if (route == null) throw new RouteNotFoundException();

            if (!route.isActive() || route.isDeleted()) throw new RouteNotActiveException();

            RouteDirection direction = bus.getCurrentDirection();
            if (direction == null) {
                direction = route.getOutgoingDirection();
            }

            if (direction == null) throw new RouteDirectionNotFoundException();

            List<RouteStationNode> nodes = direction.getStationNodes();
            if (nodes == null || nodes.isEmpty()) throw new RouteStationNodeNotFoundException();


            List<StationDTO> stationDTOs = nodes.stream()
                    .map(RouteStationNode::getFromStation)
                    .map(stationConverter::toDTO)
                    .collect(Collectors.toList());

            Station lastStation = nodes.get(nodes.size() - 1).getToStation();
            stationDTOs.add(stationConverter.toDTO(lastStation));

            return new DataResponseMessage<>("Rota istasyonları başarıyla getirildi.", true, stationDTOs);

        } catch (Exception e) {
            log.error("Error getting route stations: ", e);
            return new DataResponseMessage<>("Rota istasyonları getirilirken hata oluştu.", false, null);
        }
    }


    @Override
    public DataResponseMessage<Double> getEstimatedArrivalTime(Long busId, Long stationId) {
        try {
            Bus bus = busRepository.findByIdAndIsDeletedFalse(busId)
                    .orElseThrow(() -> new BusNotFoundException(busId));

            Station targetStation = stationRepository.findById(stationId)
                    .orElseThrow(StationNotFoundException::new);

            if (!targetStation.isActive() || targetStation.isDeleted()) {
                throw new StationNotActiveException();
            }

            if (bus.getCurrentLatitude() == null || bus.getCurrentLongitude() == null) {
                throw new BusLocationNotFoundException();
            }

            RouteDirection direction = bus.getCurrentDirection();
            if (direction == null || direction.getStationNodes() == null || direction.getStationNodes().isEmpty()) {
                throw new RouteDirectionNotFoundException();
            }

            List<RouteStationNode> stationNodes = direction.getStationNodes();
            RouteStationNode currentNode = stationNodes.stream()
                    .filter(node -> {
                        Station station = node.getToStation();
                        return station != null &&
                                googleMapsService.isNear(bus.getCurrentLatitude(), bus.getCurrentLongitude(),
                                        station.getLocation().getLatitude(), station.getLocation().getLongitude(), 100);
                    })
                    .findFirst()
                    .orElseThrow(BusNotAtAnyStationException::new);

            int currentIndex = stationNodes.indexOf(currentNode);
            if (currentIndex == -1) throw new NodeNotListException();

            double totalTime = 0;
            double currentLat = bus.getCurrentLatitude();
            double currentLng = bus.getCurrentLongitude();

            for (int i = currentIndex; i < stationNodes.size(); i++) {
                Station nextStation = stationNodes.get(i).getToStation();

                Integer travelTime = googleMapsService.getEstimatedTimeInMinutes(
                        currentLat, currentLng,
                        nextStation.getLocation().getLatitude(), nextStation.getLocation().getLongitude());

                if (travelTime == null) throw new DistanceCalculationException();

                totalTime += travelTime + 1;

                currentLat = nextStation.getLocation().getLatitude();
                currentLng = nextStation.getLocation().getLongitude();

                if (nextStation.getId().equals(stationId)) break;
            }

            return new DataResponseMessage<>("Tahmini varış süresi başarıyla hesaplandı.", true, totalTime);

        } catch (Exception e) {
            log.error("Error calculating estimated arrival time: ", e);
            return new DataResponseMessage<>("Tahmini varış süresi hesaplanırken hata oluştu.", false, null);
        }
    }

    @Override
    public DataResponseMessage<CurrentStationInfoDTO> getCurrentStationInfo(Long busId) {
        try {
            Bus bus = busRepository.findByIdAndIsDeletedFalse(busId)
                    .orElseThrow(() -> new BusNotFoundException(busId));

            CurrentStationInfoDTO dto = CurrentStationInfoDTO.builder()
                    .currentStation(bus.getLastSeenStation() != null ? 
                            stationConverter.toDTO(bus.getLastSeenStation()) : null)
                    .currentStationTime(bus.getLastSeenStationTime())
                    .nextStation(bus.getNextStation() != null ? 
                            stationConverter.toDTO(bus.getNextStation()) : null)
                    .estimatedArrivalMinutes(bus.getEstimatedArrivalMinutes())
                    .routeName(bus.getAssignedRoute() != null ? bus.getAssignedRoute().getName() : null)
                    .directionName(bus.getCurrentDirection() != null ? bus.getCurrentDirection().getName() : null)
                    .currentLatitude(bus.getCurrentLatitude())
                    .currentLongitude(bus.getCurrentLongitude())
                    .lastLocationUpdate(bus.getLastLocationUpdate())
                    .build();

            return new DataResponseMessage<>("Şu anki durak bilgisi başarıyla getirildi.", true, dto);

        } catch (BusNotFoundException e) {
            log.error("Bus not found: {}", busId);
            return new DataResponseMessage<>("Otobüs bulunamadı.", false, null);
        } catch (Exception e) {
            log.error("Error getting current station info: ", e);
            return new DataResponseMessage<>("Durak bilgisi alınırken hata oluştu.", false, null);
        }
    }


    @Override
    @Transactional
    public ResponseMessage switchDirection(Long busId, String username) throws BusNotFoundException {
        try {


            SecurityUser adminOrSuperAdmin = getAdminOrSuperAdmin(username);

            Bus bus = busRepository.findById(busId)
                    .orElseThrow(() -> new BusNotFoundException(busId));

            if (!bus.isActive() || bus.isDeleted()) throw new BusInactiveException(busId);

            if (bus.getAssignedRoute() == null) {
                throw new BusAssignedRouteNotFoundException();
            }

            bus.switchDirection();
            bus.setUpdatedBy(adminOrSuperAdmin);
            busRepository.save(bus);

            log.info("Direction switched for bus: {}", bus.getNumberPlate());
            return new ResponseMessage("Otobüs yönü başarıyla değiştirildi.", true);

        } catch (Exception e) {
            log.error("Error switching bus direction: ", e);
            return new ResponseMessage("Yön değiştirilirken hata oluştu.", false);
        }
    }

    // === İSTATİSTİKLER ===

    @Override
    public DataResponseMessage<Object> getBusStatistics(String username) {
        try {

            Map<String, Object> stats = new HashMap<>();

            // Temel sayılar
            stats.put("totalBuses", busRepository.countByIsDeletedFalse());
            stats.put("activeBuses", busRepository.countByIsActiveTrueAndIsDeletedFalse());
            stats.put("inactiveBuses", busRepository.countByIsActiveFalseAndIsDeletedFalse());

            // Durum bazlı dağılım
            Map<String, Long> statusDistribution = new HashMap<>();
            for (BusStatus status : BusStatus.values()) {
                Long count = busRepository.countByStatusAndIsDeletedFalse(status);
                statusDistribution.put(status.getDisplayName(), count);
            }
            stats.put("statusDistribution", statusDistribution);

            // Şoför ataması
            stats.put("busesWithDriver", busRepository.countByDriverIsNotNullAndIsDeletedFalse());
            stats.put("busesWithoutDriver", busRepository.countByDriverIsNullAndIsDeletedFalse());

            // Rota ataması
            stats.put("busesWithRoute", busRepository.countByAssignedRouteIsNotNullAndIsDeletedFalse());
            stats.put("busesWithoutRoute", busRepository.countByAssignedRouteIsNullAndIsDeletedFalse());

            return new DataResponseMessage<>("İstatistikler başarıyla getirildi.", true, stats);

        } catch (Exception e) {
            log.error("Error getting bus statistics: ", e);
            return new DataResponseMessage<>("İstatistikler alınırken hata oluştu.", false, null);
        }
    }

    // === FİLTRELEME VE ARAMA ===

    @Override
    public DataResponseMessage<PageDTO<BusDTO>> searchByNumberPlate(String numberPlate, String username, int page, int size) {
        try {

            SecurityUser adminOrSuperAdmin = getAdminOrSuperAdmin(username);

            //admin superadmin loglama ekle
            Pageable pageable = PageRequest.of(page, size);
            Page<Bus> busPage = busRepository.findByNumberPlateContainingIgnoreCaseAndIsDeletedFalse(numberPlate, pageable);
            PageDTO<BusDTO> pageDTO = busConverter.toPageDTO(busPage);

            return new DataResponseMessage<>("Arama sonuçları getirildi.", true, pageDTO);

        } catch (Exception e) {
            log.error("Error searching buses by plate: ", e);
            return new DataResponseMessage<>("Arama yapılırken hata oluştu.", false, null);
        }
    }


    @Override
    public DataResponseMessage<PageDTO<BusDTO>> getBusesByRoute(Long routeId, String username, int page, int size) {
        try {

            SecurityUser adminOrSuperAdmin = getAdminOrSuperAdmin(username);

            Pageable pageable = PageRequest.of(page, size);
            Page<Bus> busPage = busRepository.findByAssignedRouteIdAndIsDeletedFalse(routeId, pageable);
            PageDTO<BusDTO> pageDTO = busConverter.toPageDTO(busPage);

            return new DataResponseMessage<>("Rotadaki otobüsler getirildi.", true, pageDTO);

        } catch (Exception e) {
            log.error("Error getting buses by route: ", e);
            return new DataResponseMessage<>("Rotadaki otobüsler getirilirken hata oluştu.", false, null);
        }
    }


    @Override
    public DataResponseMessage<PageDTO<BusDTO>> getBusesByDriver(Long driverId, String username, int page, int size) {
        try {
            SecurityUser adminOrSuperAdmin = getAdminOrSuperAdmin(username);


            Pageable pageable = PageRequest.of(page, size);
            Page<Bus> busPage = busRepository.findByDriverIdAndIsDeletedFalse(driverId, pageable);
            PageDTO<BusDTO> pageDTO = busConverter.toPageDTO(busPage);

            return new DataResponseMessage<>("Şoförün otobüsleri getirildi.", true, pageDTO);

        } catch (Exception e) {
            log.error("Error getting buses by driver: ", e);
            return new DataResponseMessage<>("Şoförün otobüsleri getirilirken hata oluştu.", false, null);
        }
    }

    // === DURUM YÖNETİMİ ===

    @Override
    @Transactional
    public ResponseMessage updateBusStatus(Long busId, BusStatusUpdateRequest request, String username)
            throws BusNotFoundException {
        try {


            SecurityUser adminOrSuperAdmin = getAdminOrSuperAdmin(username);

            Bus bus = busRepository.findByIdAndIsDeletedFalse(busId)
                    .orElseThrow(() -> new BusNotFoundException(busId));

            // Status'u güncelle
            if (request.getStatus() != null) {
                bus.setStatus(request.getStatus());
            }

            bus.setUpdatedBy(adminOrSuperAdmin);
            busRepository.save(bus);

            log.info("Bus status updated: {} -> {}", bus.getNumberPlate(), request.getStatus());
            return new ResponseMessage("Otobüs durumu başarıyla güncellendi.", true);

        } catch (Exception e) {
            log.error("Error updating bus status: ", e);
            return new ResponseMessage("Durum güncellenirken hata oluştu.", false);
        }
    }

    @Override
    @Transactional
    public ResponseMessage updatePassengerCount(Long busId, Integer count, String username)
            throws BusNotFoundException {
        try {


            SecurityUser adminOrSuperAdmin = getAdminOrSuperAdmin(username);

            Bus bus = busRepository.findByIdAndIsDeletedFalse(busId)
                    .orElseThrow(() -> new BusNotFoundException(busId));

            // Yolcu sayısı validasyonu
            if (count < 0) {
                return new ResponseMessage("Yolcu sayısı negatif olamaz.", false);
            }



            bus.setUpdatedBy(adminOrSuperAdmin);
            busRepository.save(bus);

            log.info("Passenger count updated: {} -> {}", bus.getNumberPlate(), count);
            return new ResponseMessage("Yolcu sayısı başarıyla güncellendi.", true);

        } catch (Exception e) {
            log.error("Error updating passenger count: ", e);
            return new ResponseMessage("Yolcu sayısı güncellenirken hata oluştu.", false);
        }
    }

    // === TOPLU İŞLEMLER ===

    @Override
    @Transactional
    public ResponseMessage bulkActivate(List<Long> busIds, String username) {
        try {


            SecurityUser adminOrSuperAdmin = getAdminOrSuperAdmin(username);
            int updatedCount = 0;

            for (Long busId : busIds) {
                Optional<Bus> busOpt = busRepository.findById(busId);
                if (busOpt.isPresent()) {
                    Bus bus = busOpt.get();
                    if (!bus.isActive()) {
                        bus.setActive(true);
                        bus.setDeleted(false);
                        bus.setStatus(BusStatus.CALISIYOR);
                        bus.setUpdatedBy(adminOrSuperAdmin);
                        busRepository.save(bus);
                        updatedCount++;
                    }
                }
            }

            log.info("Bulk activate completed: {} buses activated", updatedCount);
            return new ResponseMessage(updatedCount + " otobüs başarıyla aktif hale getirildi.", true);

        } catch (Exception e) {
            log.error("Error in bulk activate: ", e);
            return new ResponseMessage("Toplu aktifleştirme sırasında hata oluştu.", false);
        }
    }

    @Override
    @Transactional
    public ResponseMessage bulkDeactivate(List<Long> busIds, String username) {
        try {

            SecurityUser adminOrSuperAdmin = getAdminOrSuperAdmin(username);
            int updatedCount = 0;

            for (Long busId : busIds) {
                Optional<Bus> busOpt = busRepository.findByIdAndIsDeletedFalse(busId);
                if (busOpt.isPresent()) {
                    Bus bus = busOpt.get();
                    if (bus.isActive()) {
                        bus.setActive(false);
                        bus.setDeleted(true);
                        bus.setStatus(BusStatus.SERVIS_DISI);bus.setUpdatedBy(adminOrSuperAdmin);
                        busRepository.save(bus);
                        updatedCount++;
                    }
                }
            }

            log.info("Bulk deactivate completed: {} buses deactivated", updatedCount);
            return new ResponseMessage(updatedCount + " otobüs başarıyla pasif hale getirildi.", true);

        } catch (Exception e) {
            log.error("Error in bulk deactivate: ", e);
            return new ResponseMessage("Toplu pasifleştirme sırasında hata oluştu.", false);
        }
    }

    @Override
    public ResponseMessage assignDriver(Long busId, String username)
            throws BusNotFoundException, DriverInactiveException, DriverAlreadyAssignedException, DriverNotFoundException {

        Driver driver = driverRepository.findByUserNumber(username);

        if (driver == null) {
            throw new DriverNotFoundException();
        }

        Bus bus = busRepository.findById(busId)
                .orElseThrow(() -> new BusNotFoundException(busId));

        if (!bus.isActive() || bus.isDeleted()) {
            throw new BusNotFoundException(busId);
        }

        if (!driver.getActive()) {
            throw new DriverInactiveException(driver.getId());
        }

        // Şoförün zaten bir otobüsü varsa atama yapma
        if (driver.getAssignedBus() != null) {
            Bus assignedBus = driver.getAssignedBus();
            // Aynı otobüsse tekrar atamaya gerek yok
            if (assignedBus.getId().equals(busId)) {
                return new ResponseMessage("Şoför zaten bu otobüse atanmış.", false);
            } else {
                throw new DriverAlreadyAssignedException(driver.getId());
            }
        }

        // Otobüste başka bir şoför varsa boşalt
        if (bus.getDriver() != null && !bus.getDriver().getId().equals(driver.getId())) {
            bus.setDriver(null);
        }

        bus.setDriver(driver);
        busRepository.save(bus);

        log.info("Driver assigned to bus: {} -> {}", driver.getId(), bus.getNumberPlate());
        return new ResponseMessage("Şoför başarıyla otobüse atandı.", true);
    }

    @Override
    public DataResponseMessage<PageDTO<BusDTO>> getBusesByStatus(String status, String username, int page, int size) {
        try {
            SecurityUser adminOrSuperAdmin = getAdminOrSuperAdmin(username);


            BusStatus busStatus = BusStatus.valueOf(status.toUpperCase());
            Pageable pageable = PageRequest.of(page, size);
            Page<Bus> busPage = busRepository.findByStatusAndIsDeletedFalse(busStatus, pageable);

            PageDTO<BusDTO> pageDTO = busConverter.toPageDTO(busPage);

            return new DataResponseMessage<>("Durumdaki otobüsler getirildi.", true, pageDTO);

        } catch (IllegalArgumentException e) {
            return new DataResponseMessage<>("Geçersiz durum değeri.", false, null);
        } catch (Exception e) {
            log.error("Error getting buses by status: ", e);
            return new DataResponseMessage<>("Durumdaki otobüsler getirilirken hata oluştu.", false, null);
        }
    }


    // === YARDIMCI METOTLAR ===


    private Station findClosestStation(double latitude, double longitude) {
        List<Station> allStations = stationRepository.findAllByActiveTrue();

        Station closest = null;
        double minDistance = Double.MAX_VALUE;

        for (Station station : allStations) {
            if (station.getLocation() != null) {
                double distance = calculateDistance(latitude, longitude,
                        station.getLocation().getLatitude(), station.getLocation().getLongitude());
                if (distance < minDistance) {
                    minDistance = distance;
                    closest = station;
                }
            }
        }

        return closest;
    }

    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        // Haversine formülü - basit mesafe hesaplama
        final int R = 6371; // Earth's radius in kilometers

        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);
        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c * 1000; // Metre cinsinden döndür
    }

    /**
     * Otobüsün rotasındaki en yakın durağı bulur ve lastSeenStation ile nextStation'ı günceller
     */
    private void updateBusStationInfo(Bus bus, double latitude, double longitude) {
        RouteDirection direction = bus.getCurrentDirection();
        if (direction == null || direction.getStationNodes() == null || direction.getStationNodes().isEmpty()) {
            return;
        }

        List<RouteStationNode> stationNodes = direction.getStationNodes().stream()
                .sorted((a, b) -> Integer.compare(a.getSequenceOrder(), b.getSequenceOrder()))
                .collect(Collectors.toList());

        if (stationNodes.isEmpty()) {
            return;
        }

        // En yakın durağı bul (100m mesafe içinde)
        Station closestStationInRoute = null;
        double minDistance = Double.MAX_VALUE;
        RouteStationNode closestNode = null;

        for (RouteStationNode node : stationNodes) {
            Station fromStation = node.getFromStation();
            Station toStation = node.getToStation();

            if (fromStation != null && fromStation.getLocation() != null) {
                double distance = calculateDistance(latitude, longitude,
                        fromStation.getLocation().getLatitude(), fromStation.getLocation().getLongitude());
                if (distance < minDistance && distance <= 100) { // 100m mesafe içinde
                    minDistance = distance;
                    closestStationInRoute = fromStation;
                    closestNode = node;
                }
            }

            if (toStation != null && toStation.getLocation() != null) {
                double distance = calculateDistance(latitude, longitude,
                        toStation.getLocation().getLatitude(), toStation.getLocation().getLongitude());
                if (distance < minDistance && distance <= 100) { // 100m mesafe içinde
                    minDistance = distance;
                    closestStationInRoute = toStation;
                    closestNode = node;
                }
            }
        }

        // Eğer yakın bir durak bulunduysa güncelle
        if (closestStationInRoute != null && closestNode != null) {
            bus.setLastSeenStation(closestStationInRoute);
            bus.setLastSeenStationTime(LocalDateTime.now());

            // Sonraki durağı bul
            int currentIndex = stationNodes.indexOf(closestNode);
            if (currentIndex >= 0 && currentIndex < stationNodes.size() - 1) {
                Station nextStation = stationNodes.get(currentIndex + 1).getToStation();
                if (nextStation != null) {
                    bus.setNextStation(nextStation);
                    // Tahmini varış süresini hesapla
                    try {
                        if (nextStation.getLocation() != null) {
                            Integer eta = googleMapsService.getEstimatedTimeInMinutes(
                                    latitude, longitude,
                                    nextStation.getLocation().getLatitude(),
                                    nextStation.getLocation().getLongitude());
                            bus.setEstimatedArrivalMinutes(eta);
                        }
                    } catch (Exception e) {
                        log.debug("Could not calculate ETA for next station: {}", e.getMessage());
                    }
                }
            } else {
                // Son durağa ulaşıldıysa nextStation'ı null yap
                bus.setNextStation(null);
                bus.setEstimatedArrivalMinutes(null);
            }
        }
    }
}