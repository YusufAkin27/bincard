package akin.city_card.bus.controller;

import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.core.request.*;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.CurrentStationInfoDTO;
import akin.city_card.bus.core.response.StationDTO;
import akin.city_card.bus.exceptions.*;
import akin.city_card.bus.service.abstracts.BusService;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.route.exceptions.RouteNotActiveException;
import akin.city_card.security.exception.UserNotFoundException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping("/v1/api/bus")
@RequiredArgsConstructor
@Slf4j
public class BusController {

    private final BusService busService;

    private void isAdminOrSuperAdmin(UserDetails userDetails) throws UnauthorizedAccessException {
        if (userDetails == null || userDetails.getAuthorities() == null) {
            throw new UnauthorizedAccessException();
        }

        boolean authorized = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ADMIN_ALL") || role.equals("SUPERADMIN") || role.equals("BUS_ADMIN"));

        if (!authorized) {
            throw new UnauthorizedAccessException();
        }
    }


    // === GENEL SORGULAMA ENDPOİNTLERİ ===

    @GetMapping("/all")
    public ResponseEntity<DataResponseMessage<PageDTO<BusDTO>>> getAllBuses(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        try {
            DataResponseMessage<PageDTO<BusDTO>> response = busService.getAllBuses(page, size);
            return ResponseEntity.ok(response);
        } catch (UnauthorizedAreaException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new DataResponseMessage<>("Bu alana erişim yetkiniz yok.", false, null));
        } catch (Exception e) {
            log.error("Error getting all buses: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Sistem hatası oluştu.", false, null));
        }
    }


    @GetMapping("/{busId}")
    public ResponseEntity<DataResponseMessage<BusDTO>> getBusById(
            @PathVariable Long busId,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            DataResponseMessage<BusDTO> response = busService.getBusById(busId, userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (BusNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new DataResponseMessage<>("Otobüs bulunamadı.", false, null));
        } catch (UnauthorizedAreaException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new DataResponseMessage<>("Bu alana erişim yetkiniz yok.", false, null));
        } catch (Exception e) {
            log.error("Error getting bus by ID: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Sistem hatası oluştu.", false, null));
        }
    }

    @GetMapping("/active")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<DataResponseMessage<PageDTO<BusDTO>>> getActiveBuses(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        try {
            isAdminOrSuperAdmin(userDetails);


            DataResponseMessage<PageDTO<BusDTO>> response = busService.getActiveBuses(userDetails.getUsername(), page, size);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting active buses: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Sistem hatası oluştu.", false, null));
        }
    }


    // === CRUD İŞLEMLERİ ===

    @PostMapping("/create")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage createBus(
            @Valid @RequestBody CreateBusRequest request,
            @AuthenticationPrincipal UserDetails userDetails) throws UnauthorizedAreaException, DriverNotFoundException, AdminNotFoundException, DriverAlreadyAssignedToBusException, DriverInactiveException, DuplicateBusPlateException, BusAlreadyAssignedAnotherDriverException, RouteNotFoundException, UnauthorizedAccessException, UserNotFoundException, RouteNotActiveException {

        isAdminOrSuperAdmin(userDetails);

        return busService.createBus(request, userDetails.getUsername());
    }


    @PutMapping("/update/{busId}")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> updateBus(
            @PathVariable Long busId,
            @Valid @RequestBody UpdateBusRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            isAdminOrSuperAdmin(userDetails);


            ResponseMessage response = busService.updateBus(busId, request, userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (BusNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ResponseMessage("Otobüs bulunamadı.", false));
        } catch (DuplicateBusPlateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ResponseMessage("Bu plaka zaten başka bir otobüste kayıtlı.", false));
        } catch (DriverNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ResponseMessage("Belirtilen şoför bulunamadı.", false));
        } catch (RouteNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ResponseMessage("Belirtilen rota bulunamadı.", false));
        } catch (Exception e) {
            log.error("Error updating bus: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Otobüs güncellenirken hata oluştu.", false));
        }
    }

    @DeleteMapping("/delete/{busId}")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> deleteBus(
            @PathVariable Long busId,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            isAdminOrSuperAdmin(userDetails);


            ResponseMessage response = busService.deleteBus(busId, userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (BusNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ResponseMessage("Otobüs bulunamadı.", false));
        } catch (Exception e) {
            log.error("Error deleting bus: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Otobüs silinirken hata oluştu.", false));
        }
    }

    @PutMapping("/{busId}/toggle-active")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> toggleActiveStatus(
            @PathVariable Long busId,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            isAdminOrSuperAdmin(userDetails);


            ResponseMessage response = busService.toggleBusActive(busId, userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (BusNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ResponseMessage("Otobüs bulunamadı.", false));
        } catch (Exception e) {
            log.error("Error toggling bus active status: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Otobüs durumu değiştirilirken hata oluştu.", false));
        }
    }

    // === ŞOFÖR YÖNETİMİ ===

    @PutMapping("/{busId}/assign-driver")
    @PreAuthorize("hasAuthority('DRIVER')")
    public ResponseMessage assignDriverToBus(
            @PathVariable Long busId,
            @AuthenticationPrincipal UserDetails userDetails) throws DriverAlreadyAssignedException, DriverNotFoundException, BusNotFoundException, DriverInactiveException {

         return busService.assignDriver(busId,  userDetails.getUsername());
    }

    // === KONUM YÖNETİMİ ===

    @GetMapping("/{busId}/location")
    public ResponseEntity<DataResponseMessage<BusLocationDTO>> getCurrentBusLocation(@PathVariable Long busId,
                                                                                     @AuthenticationPrincipal UserDetails userDetails) {
        try {
            DataResponseMessage<BusLocationDTO> response = busService.getCurrentLocation(busId, userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (BusNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new DataResponseMessage<>("Otobüs bulunamadı.", false, null));
        } catch (Exception e) {
            log.error("Error getting current bus location: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Konum bilgisi alınırken hata oluştu.", false, null));
        }
    }

    @PostMapping("/{busId}/location")
    public ResponseEntity<ResponseMessage> updateBusLocation(
            @PathVariable Long busId,
            @Valid @RequestBody UpdateLocationRequest request) {
        try {
            ResponseMessage response = busService.updateLocation(busId, request);
            return ResponseEntity.ok(response);
        } catch (BusNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ResponseMessage("Otobüs bulunamadı.", false));
        } catch (UnauthorizedLocationUpdateException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ResponseMessage("Konum güncelleme yetkisi yok.", false));
        } catch (Exception e) {
            log.error("Error updating bus location: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Konum güncellenirken hata oluştu.", false));
        }
    }

    @GetMapping("/{busId}/location-history")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<DataResponseMessage<PageDTO<BusLocationDTO>>> getLocationHistory(
            @PathVariable Long busId,
            @RequestParam(required = false) LocalDate date,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            isAdminOrSuperAdmin(userDetails);

            DataResponseMessage<PageDTO<BusLocationDTO>> response =
                    busService.getLocationHistory(busId, date, userDetails.getUsername(), page, size);

            return ResponseEntity.ok(response);
        } catch (BusNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new DataResponseMessage<>("Otobüs bulunamadı.", false, null));
        } catch (UnauthorizedAccessException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new DataResponseMessage<>("Bu bilgilere erişim yetkiniz yok.", false, null));
        } catch (Exception e) {
            log.error("Error getting location history: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Konum geçmişi alınırken hata oluştu.", false, null));
        }
    }


    // === ROTA YÖNETİMİ ===

    @PutMapping("/{busId}/route")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> assignRouteToBus(
            @PathVariable Long busId,
            @Valid @RequestBody AssignRouteRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            isAdminOrSuperAdmin(userDetails);

            ResponseMessage response = busService.assignRoute(busId, request.getRouteId(), userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error assigning route to bus: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Rota ataması yapılırken hata oluştu.", false));
        }
    }

    @GetMapping("/{busId}/route/stations")
    public ResponseEntity<DataResponseMessage<List<StationDTO>>> getRouteStations(
            @PathVariable Long busId,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            DataResponseMessage<List<StationDTO>> response = busService.getRouteStations(busId, userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting route stations: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Rota istasyonları alınırken hata oluştu.", false, null));
        }
    }

    @GetMapping("/{busId}/eta")
    public ResponseEntity<DataResponseMessage<Double>> getEstimatedTimeToStation(
            @PathVariable Long busId,
            @RequestParam Long stationId) {
        try {
            DataResponseMessage<Double> response = busService.getEstimatedArrivalTime(busId, stationId);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting estimated arrival time: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Tahmini varış süresi hesaplanırken hata oluştu.", false, null));
        }
    }

    @GetMapping("/{busId}/current-station-info")
    public ResponseEntity<DataResponseMessage<CurrentStationInfoDTO>> getCurrentStationInfo(
            @PathVariable Long busId) {
        try {
            DataResponseMessage<CurrentStationInfoDTO> response = busService.getCurrentStationInfo(busId);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting current station info: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Durak bilgisi alınırken hata oluştu.", false, null));
        }
    }

    // === YÖN YÖNETİMİ ===

    @PutMapping("/{busId}/switch-direction")
    public ResponseEntity<ResponseMessage> switchBusDirection(
            @PathVariable Long busId,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            ResponseMessage response = busService.switchDirection(busId, userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (BusNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ResponseMessage("Otobüs bulunamadı.", false));
        } catch (Exception e) {
            log.error("Error switching bus direction: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Yön değiştirilirken hata oluştu.", false));
        }
    }

    // === İSTATİSTİKLER ===

    @GetMapping("/statistics")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<DataResponseMessage<Object>> getBusStatistics(
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            isAdminOrSuperAdmin(userDetails);
            DataResponseMessage<Object> response = busService.getBusStatistics(userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting bus statistics: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("İstatistikler alınırken hata oluştu.", false, null));
        }
    }

    // === ARAMA VE FİLTRELEME ===

    @GetMapping("/search")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<DataResponseMessage<PageDTO<BusDTO>>> searchBuses(
            @RequestParam(required = false) String numberPlate,
            @RequestParam(required = false) Long routeId,
            @RequestParam(required = false) Long driverId,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            isAdminOrSuperAdmin(userDetails); // Yetki kontrolü

            DataResponseMessage<PageDTO<BusDTO>> response;

            if (numberPlate != null && !numberPlate.trim().isEmpty()) {
                response = busService.searchByNumberPlate(numberPlate, userDetails.getUsername(), page, size);
            } else if (routeId != null) {
                response = busService.getBusesByRoute(routeId, userDetails.getUsername(), page, size);
            } else if (driverId != null) {
                response = busService.getBusesByDriver(driverId, userDetails.getUsername(), page, size);
            } else if (status != null) {
                response = busService.getBusesByStatus(status, userDetails.getUsername(), page, size);
            } else {
                response = busService.getAllBuses(page, size);
            }

            return ResponseEntity.ok(response);
        } catch (UnauthorizedAccessException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new DataResponseMessage<>(e.getMessage(), false, null));
        } catch (Exception e) {
            log.error("Error searching buses: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Arama yapılırken hata oluştu.", false, null));
        }
    }

    @GetMapping("/route/{routeId}")
    public ResponseEntity<DataResponseMessage<PageDTO<BusDTO>>> getBusesByRoute(
            @PathVariable Long routeId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            DataResponseMessage<PageDTO<BusDTO>> response = busService.getBusesByRoute(routeId, userDetails.getUsername(), page, size);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting buses by route: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Rotadaki otobüsler getirilirken hata oluştu.", false, null));
        }
    }

    @GetMapping("/driver/{driverId}")
    public ResponseEntity<DataResponseMessage<PageDTO<BusDTO>>> getBusesByDriver(
            @PathVariable Long driverId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            DataResponseMessage<PageDTO<BusDTO>> response = busService.getBusesByDriver(driverId, userDetails.getUsername(), page, size);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting buses by driver: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Şoförün otobüsleri getirilirken hata oluştu.", false, null));
        }
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<DataResponseMessage<PageDTO<BusDTO>>> getBusesByStatus(
            @PathVariable String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            DataResponseMessage<PageDTO<BusDTO>> response = busService.getBusesByStatus(status, userDetails.getUsername(), page, size);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error getting buses by status: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new DataResponseMessage<>("Durumdaki otobüsler getirilirken hata oluştu.", false, null));
        }
    }

    // === DURUM YÖNETİMİ ===

    @PutMapping("/{busId}/status")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> updateBusStatus(
            @PathVariable Long busId,
            @Valid @RequestBody BusStatusUpdateRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            isAdminOrSuperAdmin(userDetails);


            ResponseMessage response = busService.updateBusStatus(busId, request, userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (BusNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ResponseMessage("Otobüs bulunamadı.", false));
        } catch (Exception e) {
            log.error("Error updating bus status: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Durum güncellenirken hata oluştu.", false));
        }
    }


    // === TOPLU İŞLEMLER ===

    @PutMapping("/bulk/activate")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> bulkActivateBuses(
            @RequestBody List<Long> busIds,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            isAdminOrSuperAdmin(userDetails);


            ResponseMessage response = busService.bulkActivate(busIds, userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error bulk activating buses: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Toplu aktifleştirme sırasında hata oluştu.", false));
        }
    }

    @PutMapping("/bulk/deactivate")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> bulkDeactivateBuses(
            @RequestBody List<Long> busIds,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            isAdminOrSuperAdmin(userDetails);


            ResponseMessage response = busService.bulkDeactivate(busIds, userDetails.getUsername());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error bulk deactivating buses: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Toplu pasifleştirme sırasında hata oluştu.", false));
        }
    }


}