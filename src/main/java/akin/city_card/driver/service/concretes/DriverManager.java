package akin.city_card.driver.service.concretes;

import akin.city_card.bus.exceptions.BusNotFoundException;
import akin.city_card.bus.exceptions.DriverNotFoundException;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.repository.BusRepository;
import akin.city_card.contract.service.abstacts.ContractService;
import akin.city_card.driver.core.converter.DriverConverter;
import akin.city_card.driver.core.request.CreateDriverRequest;
import akin.city_card.driver.core.request.UpdateDriverRequest;
import akin.city_card.driver.core.response.DriverDocumentDto;
import akin.city_card.driver.core.response.DriverDto;
import akin.city_card.driver.core.response.DriverPenaltyDto;
import akin.city_card.driver.core.response.DriverPerformanceDto;
import akin.city_card.driver.exceptions.*;
import akin.city_card.driver.model.Driver;
import akin.city_card.driver.model.DriverDocument;
import akin.city_card.driver.model.DriverPenalty;
import akin.city_card.driver.model.Shift;
import akin.city_card.driver.repository.DriverDocumentRepository;
import akin.city_card.driver.repository.DriverPenaltyRepository;
import akin.city_card.driver.repository.DriverRepository;
import akin.city_card.driver.service.absracts.DriverService;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.repository.SecurityUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class DriverManager implements DriverService {

    private final DriverRepository driverRepository;
    private final DriverDocumentRepository driverDocumentRepository;
    private final DriverPenaltyRepository driverPenaltyRepository;
    private final SecurityUserRepository securityUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final DriverConverter driverConverter;
    private final ContractService contractService;
    private final BusRepository busRepository;

    // Helper method to find user by username
    private SecurityUser findUserByUsername(String username) throws UserNotFoundException {
        return securityUserRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);
    }

    // Helper method to find driver by id
    private Driver findDriverById(Long id) throws DriverNotFoundException {
        return driverRepository.findByIdAndDeleteDateIsNull(id)
                .orElseThrow(() -> new DriverNotFoundException());
    }


    @Override
    public DataResponseMessage<DriverDto> createDriver(CreateDriverRequest request, String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, DriverAlreadyExistsException {
        log.info("Creating new driver by user: {}", username);

        SecurityUser currentUser = findUserByUsername(username);

        // TC kimlik no kontrolü
        if (driverRepository.existsByNationalId(request.getNationalId())) {
            log.warn("Driver already exists with national id: {}", request.getNationalId());
            throw new DriverAlreadyExistsException("TC kimlik numarası", request.getNationalId());
        }

        // Email kontrolü
        if (driverRepository.existsByProfileInfo_Email(request.getEmail())) {
            log.warn("Driver already exists with email: {}", request.getEmail());
            throw new DriverAlreadyExistsException("email adresi", request.getEmail());
        }
        ProfileInfo profileInfo = new ProfileInfo();
        profileInfo.setName(request.getFirstName());
        profileInfo.setSurname(request.getLastName());
        profileInfo.setEmail(request.getEmail());
        String password = "123456";
        Driver driver = Driver.builder()
                .profileInfo(profileInfo)
                .nationalId(request.getNationalId())
                .dateOfBirth(request.getDateOfBirth())
                .licenseClass(request.getLicenseClass())
                .licenseNumber(request.getLicenseNumber())
                .licenseExpiryDate(request.getLicenseExpiryDate())
                .licenseIssueDate(request.getLicenseIssueDate())
                .address(request.getAddress())
                .shift(request.getShift())
                .password(passwordEncoder.encode(password))
                .active(true)
                .totalDrivingHours(0L)
                .totalDistanceDriven(0.0)
                .totalPassengersTransported(0L)
                .totalEarnings(BigDecimal.ZERO)
                .averageRating(0.0)
                .createdBy(currentUser)
                .createDate(LocalDateTime.now())
                .build();

        Driver savedDriver = driverRepository.save(driver);
        DriverDto driverDto = driverConverter.toDto(savedDriver);

        String ipAddress = extractClientIp(httpServletRequest);
        String userAgent = httpServletRequest.getHeader("User-Agent");

        try {
            contractService.autoAcceptMandatoryContracts(driver, ipAddress, userAgent);
            log.info("Zorunlu sözleşmeler otomatik kabul edildi - Kullanıcı: {}", request.getNationalId());
        } catch (Exception e) {
            log.error("Zorunlu sözleşmeler otomatik kabul edilirken hata - Kullanıcı: {}", request.getNationalId(), e);
            // Sözleşme kabul hatası kullanıcı kaydını engellemez, sadece log'lanır
        }

        log.info("Successfully created driver with id: {} by user: {}", savedDriver.getId(), username);
        return new DataResponseMessage<>("Sürücü başarıyla oluşturuldu", true, driverDto);
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp.trim();
        }

        return request.getRemoteAddr();
    }


    @Override
    public DataResponseMessage<DriverDto> updateDriver(Long id, UpdateDriverRequest dto, String username) throws UserNotFoundException, DriverNotFoundException {
        log.info("Updating driver id: {} by user: {}", id, username);

        SecurityUser currentUser = findUserByUsername(username);
        Driver driver = findDriverById(id);

        // Güncelleme alanları
        if (dto.getAddress() != null) {
            driver.setAddress(dto.getAddress());
        }
        if (dto.getLicenseExpiryDate() != null) {
            driver.setLicenseExpiryDate(dto.getLicenseExpiryDate());
        }
        if (dto.getLicenseIssueDate() != null) {
            driver.setLicenseIssueDate(dto.getLicenseIssueDate());
        }
        if (dto.getLicenseClass() != null) {
            driver.setLicenseClass(dto.getLicenseClass());
        }
        if (dto.getLicenseNumber() != null) {
            driver.setLicenseNumber(dto.getLicenseNumber());
        }
        if (dto.getShift() != null) {
            driver.setShift(dto.getShift());
        }
        if (dto.getActive() != null) {
            driver.setActive(dto.getActive());
        }

        driver.setUpdatedBy(currentUser);
        driver.setUpdateDate(LocalDateTime.now());

        Driver updatedDriver = driverRepository.save(driver);
        DriverDto driverDto = driverConverter.toDto(updatedDriver);

        log.info("Successfully updated driver id: {} by user: {}", id, username);
        return new DataResponseMessage<>("Sürücü başarıyla güncellendi", true, driverDto);
    }

    @Override
    public DataResponseMessage<Void> deleteDriver(Long id, String username) throws UserNotFoundException, DriverNotFoundException {
        log.info("Deleting driver id: {} by user: {}", id, username);

        SecurityUser currentUser = findUserByUsername(username);
        Driver driver = findDriverById(id);

        // Soft delete
        driver.setDeletedBy(currentUser);
        driver.setDeleteDate(LocalDateTime.now());
        driver.setActive(false);

        driverRepository.save(driver);

        log.info("Successfully deleted driver id: {} by user: {}", id, username);
        return new DataResponseMessage<>("Sürücü başarıyla silindi", true, null);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<DriverDto> getDriverById(Long id, String username) throws DriverNotFoundException {
        log.info("Getting driver by id: {} by user: {}", id, username);

        Driver driver = findDriverById(id);
        DriverDto driverDto = driverConverter.toDto(driver);

        log.info("Successfully retrieved driver id: {}", id);
        return new DataResponseMessage<>("Sürücü başarıyla getirildi", true, driverDto);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<DriverDto>> getAllDrivers(int page, int size, String username) {
        log.info("Getting all drivers page: {}, size: {} by user: {}", page, size, username);

        Pageable pageable = PageRequest.of(page, size, Sort.by("createDate").descending());
        Page<Driver> driverPage = driverRepository.findAllByDeleteDateIsNull(pageable);

        List<DriverDto> driverDtos = driverPage.getContent().stream()
                .map(driverConverter::toDto)
                .collect(Collectors.toList());

        PageDTO<DriverDto> pageDTO = createPageDTO(driverPage, driverDtos);

        log.info("Successfully retrieved {} drivers", driverDtos.size());
        return new DataResponseMessage<>("Sürücüler başarıyla getirildi", true, pageDTO);
    }

    private <T> PageDTO<T> createPageDTO(Page<?> page, List<T> content) {
        return PageDTO.<T>builder()
                .content(content)
                .pageNumber(page.getNumber())
                .pageSize(page.getSize())
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .build();
    }


    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<DriverDocumentDto>> getDriverDocuments(Long id, Pageable pageable, String username) throws DriverNotFoundException {
        log.info("Getting driver documents for driver id: {} by user: {}", id, username);

        // Driver'ın varlığını kontrol et
        findDriverById(id);

        Page<DriverDocument> documentPage = driverDocumentRepository.findByDriverIdOrderByIdDesc(id, pageable);

        List<DriverDocumentDto> documentDtos = documentPage.getContent().stream()
                .map(doc -> DriverDocumentDto.builder()
                        .id(doc.getId())
                        .documentName(doc.getDocumentName())
                        .documentType(doc.getDocumentType())
                        .expiryDate(doc.getExpiryDate())
                        .filePath(doc.getFilePath())
                        .build())
                .collect(Collectors.toList());

        PageDTO<DriverDocumentDto> pageDTO = createPageDTO(documentPage, documentDtos);

        return new DataResponseMessage<>("Sürücü belgeleri başarıyla getirildi", true, pageDTO);
    }


    @Override
    public DataResponseMessage<DriverDocumentDto> addDriverDocument(Long id, DriverDocumentDto dto, String username) throws DriverNotFoundException {
        log.info("Adding document to driver id: {} by user: {}", id, username);

        Driver driver = findDriverById(id);

        DriverDocument document = DriverDocument.builder()
                .documentName(dto.getDocumentName())
                .documentType(dto.getDocumentType())
                .expiryDate(dto.getExpiryDate())
                .filePath(dto.getFilePath())
                .driver(driver)
                .build();

        DriverDocument savedDocument = driverDocumentRepository.save(document);

        DriverDocumentDto resultDto = DriverDocumentDto.builder()
                .id(savedDocument.getId())
                .documentName(savedDocument.getDocumentName())
                .documentType(savedDocument.getDocumentType())
                .expiryDate(savedDocument.getExpiryDate())
                .filePath(savedDocument.getFilePath())
                .build();

        return new DataResponseMessage<>("Sürücü belgesi başarıyla eklendi", true, resultDto);
    }

    @Override
    public DataResponseMessage<DriverDocumentDto> updateDriverDocument(Long docId, DriverDocumentDto dto, String username) throws DriverDocumentNotFoundException {
        log.info("Updating driver document id: {} by user: {}", docId, username);

        DriverDocument document = driverDocumentRepository.findById(docId)
                .orElseThrow(() -> new DriverDocumentNotFoundException(docId));

        if (dto.getDocumentName() != null) {
            document.setDocumentName(dto.getDocumentName());
        }
        if (dto.getDocumentType() != null) {
            document.setDocumentType(dto.getDocumentType());
        }
        if (dto.getExpiryDate() != null) {
            document.setExpiryDate(dto.getExpiryDate());
        }
        if (dto.getFilePath() != null) {
            document.setFilePath(dto.getFilePath());
        }

        DriverDocument updatedDocument = driverDocumentRepository.save(document);

        DriverDocumentDto resultDto = DriverDocumentDto.builder()
                .id(updatedDocument.getId())
                .documentName(updatedDocument.getDocumentName())
                .documentType(updatedDocument.getDocumentType())
                .expiryDate(updatedDocument.getExpiryDate())
                .filePath(updatedDocument.getFilePath())
                .build();

        return new DataResponseMessage<>("Sürücü belgesi başarıyla güncellendi", true, resultDto);
    }

    @Override
    public DataResponseMessage<Void> deleteDriverDocument(Long docId, String username) throws DriverDocumentNotFoundException {
        log.info("Deleting driver document id: {} by user: {}", docId, username);

        if (!driverDocumentRepository.existsById(docId)) {
            throw new DriverDocumentNotFoundException(docId);
        }

        driverDocumentRepository.deleteById(docId);
        return new DataResponseMessage<>("Sürücü belgesi başarıyla silindi", true, null);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<DriverPenaltyDto>> getDriverPenalties(Long id, Pageable pageable, String username) throws DriverNotFoundException {
        log.info("Getting driver penalties for driver id: {} by user: {}", id, username);

        // Driver'ın varlığını kontrol et
        findDriverById(id);

        Page<DriverPenalty> penaltyPage = driverPenaltyRepository.findByDriverIdOrderByDateDesc(id, pageable);

        List<DriverPenaltyDto> penaltyDtos = penaltyPage.getContent().stream()
                .map(penalty -> DriverPenaltyDto.builder()
                        .id(penalty.getId())
                        .reason(penalty.getReason())
                        .date(penalty.getDate())
                        .amount(penalty.getAmount())
                        .build())
                .collect(Collectors.toList());

        PageDTO<DriverPenaltyDto> pageDTO = createPageDTO(penaltyPage, penaltyDtos);

        return new DataResponseMessage<>("Sürücü cezaları başarıyla getirildi", true, pageDTO);
    }

    @Override
    public DataResponseMessage<DriverPenaltyDto> addDriverPenalty(Long id, DriverPenaltyDto dto, String username) throws DriverNotFoundException {
        log.info("Adding penalty to driver id: {} by user: {}", id, username);

        Driver driver = findDriverById(id);

        DriverPenalty penalty = DriverPenalty.builder()
                .reason(dto.getReason())
                .date(dto.getDate() != null ? dto.getDate() : LocalDate.now())
                .amount(dto.getAmount())
                .driver(driver)
                .build();

        DriverPenalty savedPenalty = driverPenaltyRepository.save(penalty);

        DriverPenaltyDto resultDto = DriverPenaltyDto.builder()
                .id(savedPenalty.getId())
                .reason(savedPenalty.getReason())
                .date(savedPenalty.getDate())
                .amount(savedPenalty.getAmount())
                .build();

        return new DataResponseMessage<>("Sürücü cezası başarıyla eklendi", true, resultDto);
    }

    @Override
    public DataResponseMessage<DriverPenaltyDto> updateDriverPenalty(Long penaltyId, DriverPenaltyDto dto, String username) throws DriverPenaltyNotFoundException {
        log.info("Updating driver penalty id: {} by user: {}", penaltyId, username);

        DriverPenalty penalty = driverPenaltyRepository.findById(penaltyId)
                .orElseThrow(() -> new DriverPenaltyNotFoundException(penaltyId));

        if (dto.getReason() != null) {
            penalty.setReason(dto.getReason());
        }
        if (dto.getDate() != null) {
            penalty.setDate(dto.getDate());
        }
        if (dto.getAmount() != null) {
            penalty.setAmount(dto.getAmount());
        }

        DriverPenalty updatedPenalty = driverPenaltyRepository.save(penalty);

        DriverPenaltyDto resultDto = DriverPenaltyDto.builder()
                .id(updatedPenalty.getId())
                .reason(updatedPenalty.getReason())
                .date(updatedPenalty.getDate())
                .amount(updatedPenalty.getAmount())
                .build();

        return new DataResponseMessage<>("Sürücü cezası başarıyla güncellendi", true, resultDto);
    }

    @Override
    public DataResponseMessage<Void> deleteDriverPenalty(Long penaltyId, String username) throws DriverPenaltyNotFoundException {
        log.info("Deleting driver penalty id: {} by user: {}", penaltyId, username);

        if (!driverPenaltyRepository.existsById(penaltyId)) {
            throw new DriverPenaltyNotFoundException(penaltyId);
        }

        driverPenaltyRepository.deleteById(penaltyId);
        return new DataResponseMessage<>("Sürücü cezası başarıyla silindi", true, null);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<DriverPerformanceDto> getDriverPerformance(Long id, String username) throws DriverNotFoundException {
        log.info("Getting driver performance for id: {} by user: {}", id, username);

        Driver driver = findDriverById(id);

        DriverPerformanceDto performanceDto = DriverPerformanceDto.builder()
                .totalDrivingHours(driver.getTotalDrivingHours())
                .totalDistanceDriven(driver.getTotalDistanceDriven())
                .totalPassengersTransported(driver.getTotalPassengersTransported())
                .totalEarnings(driver.getTotalEarnings())
                .averageRating(driver.getAverageRating())
                .build();

        log.info("Successfully retrieved performance data for driver id: {}", id);
        return new DataResponseMessage<>("Sürücü performans bilgileri başarıyla getirildi", true, performanceDto);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<DriverDto>> getActiveDrivers(int page, int size, String username) {
        log.info("Getting active drivers page: {}, size: {} by user: {}", page, size, username);

        Pageable pageable = PageRequest.of(page, size, Sort.by("firstName").ascending());
        Page<Driver> driverPage = driverRepository.findByActiveAndDeleteDateIsNull(true, pageable);

        List<DriverDto> driverDtos = driverPage.getContent().stream()
                .map(driverConverter::toDto)
                .collect(Collectors.toList());

        PageDTO<DriverDto> pageDTO = createPageDTO(driverPage, driverDtos);

        return new DataResponseMessage<>("Aktif sürücüler başarıyla getirildi", true, pageDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<DriverDto>> getDriversByShift(String shift, int page, int size, String username) throws InvalidShiftTypeException {
        log.info("Getting drivers by shift: {} page: {}, size: {} by user: {}", shift, page, size, username);

        Shift shiftEnum;
        try {
            shiftEnum = Shift.valueOf(shift.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new InvalidShiftTypeException(shift);
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("firstName").ascending());
        Page<Driver> driverPage = driverRepository.findByShiftAndActiveAndDeleteDateIsNull(shiftEnum, true, pageable);

        List<DriverDto> driverDtos = driverPage.getContent().stream()
                .map(driverConverter::toDto)
                .collect(Collectors.toList());

        PageDTO<DriverDto> pageDTO = createPageDTO(driverPage, driverDtos);

        return new DataResponseMessage<>(shift + " vardiyasındaki sürücüler başarıyla getirildi", true, pageDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<DriverDto>> searchDrivers(String query, int page, int size, String username) {
        log.info("Searching drivers with query: '{}' page: {}, size: {} by user: {}", query, page, size, username);

        Pageable pageable = PageRequest.of(page, size, Sort.by("firstName").ascending());
        Page<Driver> driverPage = driverRepository.findBySearchQuery(query.toLowerCase(), pageable);

        List<DriverDto> driverDtos = driverPage.getContent().stream()
                .map(driverConverter::toDto)
                .collect(Collectors.toList());

        PageDTO<DriverDto> pageDTO = createPageDTO(driverPage, driverDtos);

        return new DataResponseMessage<>("Arama sonuçları başarıyla getirildi", true, pageDTO);
    }

    @Override
    public DataResponseMessage<DriverDto> changeDriverStatus(Long id, Boolean active, String username) throws UserNotFoundException, DriverNotFoundException {
        log.info("Changing driver status id: {} to active: {} by user: {}", id, active, username);

        SecurityUser currentUser = findUserByUsername(username);
        Driver driver = findDriverById(id);

        driver.setActive(active);
        driver.setUpdatedBy(currentUser);
        driver.setUpdateDate(LocalDateTime.now());

        Driver updatedDriver = driverRepository.save(driver);
        DriverDto driverDto = driverConverter.toDto(updatedDriver);

        String message = active ? "Sürücü aktif duruma getirildi" : "Sürücü pasif duruma getirildi";
        return new DataResponseMessage<>(message, true, driverDto);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<Object> getDriverStatistics(String username) {
        log.info("Getting driver statistics by user: {}", username);

        // Genel istatistikler
        long totalDrivers = driverRepository.countByDeleteDateIsNull();
        long activeDrivers = driverRepository.countByActiveAndDeleteDateIsNull(true);
        long inactiveDrivers = totalDrivers - activeDrivers;

        // Vardiya dağılımları
        long daytimeShiftDrivers = driverRepository.countByShiftAndActiveAndDeleteDateIsNull(Shift.DAYTIME, true);
        long nightShiftDrivers = driverRepository.countByShiftAndActiveAndDeleteDateIsNull(Shift.NIGHT, true);

        // Cezalı sürücü sayısı
        long driversWithPenalties = driverRepository.countDriversWithPenalties();

        // Yakında dolacak lisans sayısı (30 gün içinde)
        LocalDate thirtyDaysFromNow = LocalDate.now().plusDays(30);
        long expiringLicensesCount = driverRepository.countByLicenseExpiryDateBeforeAndActiveAndDeleteDateIsNull(thirtyDaysFromNow, true);

        // Yakında dolacak sağlık raporu sayısı (30 gün içinde)
        long expiringHealthCertificatesCount = driverRepository.countByHealthCertificateExpiryBeforeAndActiveAndDeleteDateIsNull(thirtyDaysFromNow, true);

        // Ortalama deneyim (yıl olarak)
        Double averageExperienceYears = driverRepository.getAverageExperienceYears();

        // En yüksek ve en düşük puan
        Double highestRating = driverRepository.getHighestAverageRating();
        Double lowestRating = driverRepository.getLowestAverageRating();

        // Son 30 günde eklenen sürücü sayısı
        LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);
        long newDriversLastMonth = driverRepository.countByCreateDateAfterAndDeleteDateIsNull(thirtyDaysAgo);

        Map<String, Object> statistics = new HashMap<>();
        statistics.put("totalDrivers", totalDrivers);
        statistics.put("activeDrivers", activeDrivers);
        statistics.put("inactiveDrivers", inactiveDrivers);
        statistics.put("daytimeShiftDrivers", daytimeShiftDrivers);
        statistics.put("nightShiftDrivers", nightShiftDrivers);
        statistics.put("driversWithPenalties", driversWithPenalties);
        statistics.put("expiringLicensesCount", expiringLicensesCount);
        statistics.put("expiringHealthCertificatesCount", expiringHealthCertificatesCount);
        statistics.put("averageExperienceYears", averageExperienceYears != null ? averageExperienceYears : 0.0);
        statistics.put("highestRating", highestRating != null ? highestRating : 0.0);
        statistics.put("lowestRating", lowestRating != null ? lowestRating : 0.0);
        statistics.put("newDriversLastMonth", newDriversLastMonth);

        // Performans dağılımı
        Map<String, Long> performanceDistribution = new HashMap<>();
        performanceDistribution.put("excellent", driverRepository.countByAverageRatingBetweenAndActiveAndDeleteDateIsNull(4.5, 5.0, true));
        performanceDistribution.put("good", driverRepository.countByAverageRatingBetweenAndActiveAndDeleteDateIsNull(3.5, 4.49, true));
        performanceDistribution.put("average", driverRepository.countByAverageRatingBetweenAndActiveAndDeleteDateIsNull(2.5, 3.49, true));
        performanceDistribution.put("poor", driverRepository.countByAverageRatingBetweenAndActiveAndDeleteDateIsNull(0.0, 2.49, true));
        performanceDistribution.put("unrated", driverRepository.countByAverageRatingIsNullAndActiveAndDeleteDateIsNull(true));

        statistics.put("performanceDistribution", performanceDistribution);

        return new DataResponseMessage<>("Sürücü istatistikleri başarıyla getirildi", true, statistics);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<List<DriverDto>> getDriversWithExpiringLicenses(int days, String username) {
        log.info("Getting drivers with licenses expiring in {} days by user: {}", days, username);

        LocalDate expiryDate = LocalDate.now().plusDays(days);
        List<Driver> drivers = driverRepository.findByLicenseExpiryDateBeforeAndActiveAndDeleteDateIsNullOrderByLicenseExpiryDate(expiryDate, true);

        List<DriverDto> driverDtos = drivers.stream()
                .map(driverConverter::toDto)
                .collect(Collectors.toList());

        String message = String.format("%d gün içinde lisansı dolacak %d sürücü bulundu", days, driverDtos.size());
        return new DataResponseMessage<>(message, true, driverDtos);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<List<DriverDto>> getDriversWithExpiringHealthCertificates(int days, String username) {
        log.info("Getting drivers with health certificates expiring in {} days by user: {}", days, username);

        LocalDate expiryDate = LocalDate.now().plusDays(days);
        List<Driver> drivers = driverRepository.findByHealthCertificateExpiryBeforeAndActiveAndDeleteDateIsNullOrderByHealthCertificateExpiry(expiryDate, true);

        List<DriverDto> driverDtos = drivers.stream()
                .map(driverConverter::toDto)
                .collect(Collectors.toList());

        String message = String.format("%d gün içinde sağlık raporu dolacak %d sürücü bulundu", days, driverDtos.size());
        return new DataResponseMessage<>(message, true, driverDtos);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<DriverDto>> getDriversHiredBetween(LocalDate startDate, LocalDate endDate, int page, int size, String username) throws InvalidDateRangeException {
        log.info("Getting drivers hired between {} and {} page: {}, size: {} by user: {}", startDate, endDate, page, size, username);

        if (startDate.isAfter(endDate)) {
            throw new InvalidDateRangeException();
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("employmentDate").descending());
        Page<Driver> driverPage = driverRepository.findByEmploymentDateBetweenAndDeleteDateIsNull(startDate, endDate, pageable);

        List<DriverDto> driverDtos = driverPage.getContent().stream()
                .map(driverConverter::toDto)
                .collect(Collectors.toList());

        PageDTO<DriverDto> pageDTO = createPageDTO(driverPage, driverDtos);

        String message = String.format("%s - %s tarihleri arasında işe başlayan sürücüler getirildi", startDate, endDate);
        return new DataResponseMessage<>(message, true, pageDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<List<DriverDto>> getTopPerformingDrivers(int limit, String username) throws InvalidLimitException {
        log.info("Getting top {} performing drivers by user: {}", limit, username);

        if (limit <= 0 || limit > 100) {
            throw new InvalidLimitException(1, 100);
        }

        Pageable pageable = PageRequest.of(0, limit, Sort.by("averageRating").descending().and(Sort.by("totalPassengersTransported").descending()));
        Page<Driver> driverPage = driverRepository.findByActiveAndDeleteDateIsNullAndAverageRatingIsNotNull(true, pageable);

        List<DriverDto> driverDtos = driverPage.getContent().stream()
                .map(driverConverter::toDto)
                .collect(Collectors.toList());

        String message = String.format("En yüksek performans gösteren %d sürücü getirildi", driverDtos.size());
        return new DataResponseMessage<>(message, true, driverDtos);
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<DriverDto>> getDriversWithPenalties(int page, int size, String username) {
        log.info("Getting drivers with penalties page: {}, size: {} by user: {}", page, size, username);

        Pageable pageable = PageRequest.of(page, size, Sort.by("firstName").ascending());
        Page<Driver> driverPage = driverRepository.findDriversWithPenalties(pageable);

        List<DriverDto> driverDtos = driverPage.getContent().stream()
                .map(driverConverter::toDto)
                .collect(Collectors.toList());

        PageDTO<DriverDto> pageDTO = createPageDTO(driverPage, driverDtos);

        return new DataResponseMessage<>("Cezası olan sürücüler başarıyla getirildi", true, pageDTO);
    }

    @Override
    public DriverDto getDriverProfile(String username) {
        Driver driver = driverRepository.findByUserNumber(username);
        return driverConverter.toDto(driver);
    }

    @Override
    @Transactional
    public ResponseMessage assignDriverToBus(Long busId, String username) throws BusNotFoundException {

        Driver driver = driverRepository.findByUserNumber(username);
        Bus bus = busRepository.findById(busId).orElseThrow(() -> new BusNotFoundException(busId));
        if (bus.getDriver() == null) {
            driver.setAssignedBus(bus);
            driver.setUpdateDate(LocalDateTime.now());
            driverRepository.save(driver);
            return new ResponseMessage("Süreniz başarıyla başlatıldı", true);

        }
        return new ResponseMessage("otobüs başka şöfore tanımlı", true);


    }

    @Override
    @Transactional
    public ResponseMessage unassignDriverFromBus(String username) {
        Driver driver = driverRepository.findByUserNumber(username);
        Bus bus = driver.getAssignedBus();
        driver.setAssignedBus(null);
        bus.setDriver(null);
        return new ResponseMessage("başarılı",true);
    }
}