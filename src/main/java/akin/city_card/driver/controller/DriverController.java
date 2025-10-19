package akin.city_card.driver.controller;

import akin.city_card.bus.exceptions.BusNotFoundException;
import akin.city_card.bus.exceptions.DriverNotFoundException;
import akin.city_card.driver.core.request.CreateDriverRequest;
import akin.city_card.driver.core.request.UpdateDriverRequest;
import akin.city_card.driver.core.response.DriverDocumentDto;
import akin.city_card.driver.core.response.DriverDto;
import akin.city_card.driver.core.response.DriverPenaltyDto;
import akin.city_card.driver.core.response.DriverPerformanceDto;
import akin.city_card.driver.exceptions.*;
import akin.city_card.driver.service.absracts.DriverService;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping("/v1/api/drivers")
@RequiredArgsConstructor
public class DriverController {

    private final DriverService driverService;

    // === DRIVER CRUD ===

    @PostMapping
    public DataResponseMessage<DriverDto> createDriver(@RequestBody CreateDriverRequest request,
                                                       @AuthenticationPrincipal UserDetails userDetails,
                                                       HttpServletRequest httpServletRequest) throws UserNotFoundException, DriverAlreadyExistsException {
        return driverService.createDriver(request, userDetails.getUsername(), httpServletRequest);
    }

    @PutMapping("/{id}")
    public DataResponseMessage<DriverDto> updateDriver(@PathVariable Long id,
                                                       @RequestBody UpdateDriverRequest dto,
                                                       @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, DriverNotFoundException {
        return driverService.updateDriver(id, dto, userDetails.getUsername());
    }

    @GetMapping("/profile")
    public DriverDto getDriverProfile(@AuthenticationPrincipal UserDetails userDetails) {
        return driverService.getDriverProfile(userDetails.getUsername());
    }

    @DeleteMapping("/{id}")
    public DataResponseMessage<Void> deleteDriver(@PathVariable Long id,
                                                  @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, DriverNotFoundException {
        return driverService.deleteDriver(id, userDetails.getUsername());
    }

    @GetMapping("/{id}")
    public DataResponseMessage<DriverDto> getDriverById(@PathVariable Long id,
                                                        @AuthenticationPrincipal UserDetails userDetails) throws DriverNotFoundException {
        return driverService.getDriverById(id, userDetails.getUsername());
    }

    @PostMapping("/assign-bus")
    public ResponseMessage assignDriverToBus(@AuthenticationPrincipal UserDetails userDetails, @RequestParam Long busId) throws DriverNotFoundException, BusNotFoundException {
        return driverService.assignDriverToBus(busId, userDetails.getUsername());
    }

    @DeleteMapping("/assign-bus")
    public ResponseMessage unassignDriverFromBus(@AuthenticationPrincipal UserDetails userDetails) throws DriverNotFoundException, BusNotFoundException {
        return driverService.unassignDriverFromBus( userDetails.getUsername());
    }
    @GetMapping
    public DataResponseMessage<PageDTO<DriverDto>> getAllDrivers(@RequestParam(required = false) int page,
                                                                 @RequestParam(required = false) int size,
                                                                 @AuthenticationPrincipal UserDetails userDetails) {
        return driverService.getAllDrivers(page, size, userDetails.getUsername());
    }

    // === DOCUMENTS ===

    @GetMapping("/{id}/documents")
    public DataResponseMessage<PageDTO<DriverDocumentDto>> getDriverDocuments(@PathVariable Long id,
                                                                              Pageable pageable,
                                                                              @AuthenticationPrincipal UserDetails userDetails) throws DriverNotFoundException {
        return driverService.getDriverDocuments(id, pageable, userDetails.getUsername());
    }

    @PostMapping("/{id}/documents")
    public DataResponseMessage<DriverDocumentDto> addDriverDocument(@PathVariable Long id,
                                                                    @RequestBody DriverDocumentDto dto,
                                                                    @AuthenticationPrincipal UserDetails userDetails) throws DriverNotFoundException {
        return driverService.addDriverDocument(id, dto, userDetails.getUsername());
    }

    @PutMapping("/documents/{docId}")
    public DataResponseMessage<DriverDocumentDto> updateDriverDocument(@PathVariable Long docId,
                                                                       @RequestBody DriverDocumentDto dto,
                                                                       @AuthenticationPrincipal UserDetails userDetails) throws DriverDocumentNotFoundException {
        return driverService.updateDriverDocument(docId, dto, userDetails.getUsername());
    }

    @DeleteMapping("/documents/{docId}")
    public DataResponseMessage<Void> deleteDriverDocument(@PathVariable Long docId,
                                                          @AuthenticationPrincipal UserDetails userDetails) throws DriverDocumentNotFoundException {
        return driverService.deleteDriverDocument(docId, userDetails.getUsername());
    }

    // === PENALTIES ===

    @GetMapping("/{id}/penalties")
    public DataResponseMessage<PageDTO<DriverPenaltyDto>> getDriverPenalties(@PathVariable Long id,
                                                                             Pageable pageable,
                                                                             @AuthenticationPrincipal UserDetails userDetails) throws DriverNotFoundException {
        return driverService.getDriverPenalties(id, pageable, userDetails.getUsername());
    }

    @PostMapping("/{id}/penalties")
    public DataResponseMessage<DriverPenaltyDto> addDriverPenalty(@PathVariable Long id,
                                                                  @RequestBody DriverPenaltyDto dto,
                                                                  @AuthenticationPrincipal UserDetails userDetails) throws DriverNotFoundException {
        return driverService.addDriverPenalty(id, dto, userDetails.getUsername());
    }

    @PutMapping("/penalties/{penaltyId}")
    public DataResponseMessage<DriverPenaltyDto> updateDriverPenalty(@PathVariable Long penaltyId,
                                                                     @RequestBody DriverPenaltyDto dto,
                                                                     @AuthenticationPrincipal UserDetails userDetails) throws DriverPenaltyNotFoundException {
        return driverService.updateDriverPenalty(penaltyId, dto, userDetails.getUsername());
    }

    @DeleteMapping("/penalties/{penaltyId}")
    public DataResponseMessage<Void> deleteDriverPenalty(@PathVariable Long penaltyId,
                                                         @AuthenticationPrincipal UserDetails userDetails) throws DriverPenaltyNotFoundException {
        return driverService.deleteDriverPenalty(penaltyId, userDetails.getUsername());
    }

    // === PERFORMANCE ===

    @GetMapping("/{id}/performance")
    public DataResponseMessage<DriverPerformanceDto> getDriverPerformance(@PathVariable Long id,
                                                                          @AuthenticationPrincipal UserDetails userDetails) throws DriverNotFoundException {
        return driverService.getDriverPerformance(id, userDetails.getUsername());
    }

    // === NEW ENDPOINTS ===

    // Aktif sürücüleri getir
    @GetMapping("/active")
    public DataResponseMessage<PageDTO<DriverDto>> getActiveDrivers(@RequestParam(defaultValue = "0") int page,
                                                                    @RequestParam(defaultValue = "10") int size,
                                                                    @AuthenticationPrincipal UserDetails userDetails) {
        return driverService.getActiveDrivers(page, size, userDetails.getUsername());
    }

    // Belirli vardiya tipindeki sürücüleri getir
    @GetMapping("/by-shift/{shift}")
    public DataResponseMessage<PageDTO<DriverDto>> getDriversByShift(@PathVariable String shift,
                                                                     @RequestParam(defaultValue = "0") int page,
                                                                     @RequestParam(defaultValue = "10") int size,
                                                                     @AuthenticationPrincipal UserDetails userDetails) throws InvalidShiftTypeException {
        return driverService.getDriversByShift(shift, page, size, userDetails.getUsername());
    }

    // Sürücü arama (isim, soyisim veya TC kimlik no ile)
    @GetMapping("/search")
    public DataResponseMessage<PageDTO<DriverDto>> searchDrivers(@RequestParam String query,
                                                                 @RequestParam(defaultValue = "0") int page,
                                                                 @RequestParam(defaultValue = "10") int size,
                                                                 @AuthenticationPrincipal UserDetails userDetails) {
        return driverService.searchDrivers(query, page, size, userDetails.getUsername());
    }

    // Sürücüyü aktif/pasif yapma
    @PutMapping("/{id}/status")
    public DataResponseMessage<DriverDto> changeDriverStatus(@PathVariable Long id,
                                                             @RequestParam Boolean active,
                                                             @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, DriverNotFoundException {
        return driverService.changeDriverStatus(id, active, userDetails.getUsername());
    }

    // Sürücü istatistikleri özeti
    @GetMapping("/statistics")
    public DataResponseMessage<Object> getDriverStatistics(@AuthenticationPrincipal UserDetails userDetails) {
        return driverService.getDriverStatistics(userDetails.getUsername());
    }

    // Lisansı yakında dolacak sürücüler
    @GetMapping("/expiring-licenses")
    public DataResponseMessage<List<DriverDto>> getDriversWithExpiringLicenses(@RequestParam(defaultValue = "30") int days,
                                                                               @AuthenticationPrincipal UserDetails userDetails) {
        return driverService.getDriversWithExpiringLicenses(days, userDetails.getUsername());
    }

    // Sağlık raporu yakında dolacak sürücüler
    @GetMapping("/expiring-health-certificates")
    public DataResponseMessage<List<DriverDto>> getDriversWithExpiringHealthCertificates(@RequestParam(defaultValue = "30") int days,
                                                                                         @AuthenticationPrincipal UserDetails userDetails) {
        return driverService.getDriversWithExpiringHealthCertificates(days, userDetails.getUsername());
    }

    // Belirli tarih aralığında işe başlayan sürücüler
    @GetMapping("/hired-between")
    public DataResponseMessage<PageDTO<DriverDto>> getDriversHiredBetween(@RequestParam LocalDate startDate,
                                                                          @RequestParam LocalDate endDate,
                                                                          @RequestParam(defaultValue = "0") int page,
                                                                          @RequestParam(defaultValue = "10") int size,
                                                                          @AuthenticationPrincipal UserDetails userDetails) throws InvalidDateRangeException {
        return driverService.getDriversHiredBetween(startDate, endDate, page, size, userDetails.getUsername());
    }

    // En yüksek performans gösteren sürücüler
    @GetMapping("/top-performers")
    public DataResponseMessage<List<DriverDto>> getTopPerformingDrivers(@RequestParam(defaultValue = "10") int limit,
                                                                        @AuthenticationPrincipal UserDetails userDetails) throws InvalidLimitException {
        return driverService.getTopPerformingDrivers(limit, userDetails.getUsername());
    }

    // Ceza sayısına göre sürücü listesi
    @GetMapping("/with-penalties")
    public DataResponseMessage<PageDTO<DriverDto>> getDriversWithPenalties(@RequestParam(defaultValue = "0") int page,
                                                                           @RequestParam(defaultValue = "10") int size,
                                                                           @AuthenticationPrincipal UserDetails userDetails) {
        return driverService.getDriversWithPenalties(page, size, userDetails.getUsername());
    }
}