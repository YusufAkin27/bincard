package akin.city_card.driver.service.absracts;

import akin.city_card.bus.exceptions.BusNotFoundException;
import akin.city_card.bus.exceptions.DriverNotFoundException;
import akin.city_card.driver.core.request.CreateDriverRequest;
import akin.city_card.driver.core.request.UpdateDriverRequest;
import akin.city_card.driver.core.response.DriverDocumentDto;
import akin.city_card.driver.core.response.DriverDto;
import akin.city_card.driver.core.response.DriverEarningSummaryDto;
import akin.city_card.driver.core.response.DriverPenaltyDto;
import akin.city_card.driver.core.response.DriverPerformanceDto;
import akin.city_card.driver.exceptions.*;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Pageable;

import java.time.LocalDate;
import java.util.List;

public interface DriverService {
    DataResponseMessage<DriverPerformanceDto> getDriverPerformance(Long id, String username) throws DriverNotFoundException;

    DataResponseMessage<DriverDto> createDriver(CreateDriverRequest request, String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, DriverAlreadyExistsException;

    DataResponseMessage<DriverDto> updateDriver(Long id, UpdateDriverRequest dto, String username) throws UserNotFoundException, DriverNotFoundException;

    DataResponseMessage<Void> deleteDriver(Long id, String username) throws UserNotFoundException, DriverNotFoundException;

    DataResponseMessage<DriverDto> getDriverById(Long id, String username) throws DriverNotFoundException;

    DataResponseMessage<PageDTO<DriverDto>> getAllDrivers(int page, int size, String username);

    DataResponseMessage<PageDTO<DriverDocumentDto>> getDriverDocuments(Long id, Pageable pageable, String username) throws DriverNotFoundException;

    DataResponseMessage<DriverDocumentDto> addDriverDocument(Long id, DriverDocumentDto dto, String username) throws DriverNotFoundException;

    DataResponseMessage<DriverDocumentDto> updateDriverDocument(Long docId, DriverDocumentDto dto, String username) throws DriverDocumentNotFoundException;

    DataResponseMessage<Void> deleteDriverDocument(Long docId, String username) throws DriverDocumentNotFoundException;

    DataResponseMessage<PageDTO<DriverPenaltyDto>> getDriverPenalties(Long id, Pageable pageable, String username) throws DriverNotFoundException;

    DataResponseMessage<DriverPenaltyDto> addDriverPenalty(Long id, DriverPenaltyDto dto, String username) throws DriverNotFoundException;

    DataResponseMessage<DriverPenaltyDto> updateDriverPenalty(Long penaltyId, DriverPenaltyDto dto, String username) throws DriverPenaltyNotFoundException;

    DataResponseMessage<Void> deleteDriverPenalty(Long penaltyId, String username) throws DriverPenaltyNotFoundException;

    DataResponseMessage<PageDTO<DriverDto>> getActiveDrivers(int page, int size, String username);

    DataResponseMessage<PageDTO<DriverDto>> getDriversByShift(String shift, int page, int size, String username) throws InvalidShiftTypeException;

    DataResponseMessage<PageDTO<DriverDto>> searchDrivers(String query, int page, int size, String username);

    DataResponseMessage<DriverDto> changeDriverStatus(Long id, Boolean active, String username) throws UserNotFoundException, DriverNotFoundException;

    DataResponseMessage<Object> getDriverStatistics(String username);

    DataResponseMessage<List<DriverDto>> getDriversWithExpiringLicenses(int days, String username);

    DataResponseMessage<List<DriverDto>> getDriversWithExpiringHealthCertificates(int days, String username);

    DataResponseMessage<PageDTO<DriverDto>> getDriversHiredBetween(LocalDate startDate, LocalDate endDate, int page, int size, String username) throws InvalidDateRangeException;

    DataResponseMessage<List<DriverDto>> getTopPerformingDrivers(int limit, String username) throws InvalidLimitException;

    DataResponseMessage<PageDTO<DriverDto>> getDriversWithPenalties(int page, int size, String username);

    DriverDto getDriverProfile(String username);

    DataResponseMessage<PageDTO<DriverEarningSummaryDto>> getDriverEarnings(LocalDate startDate, LocalDate endDate, int page, int size, String username) throws InvalidDateRangeException;

    DataResponseMessage<DriverEarningSummaryDto> getDriverEarning(Long driverId, LocalDate startDate, LocalDate endDate, String username) throws DriverNotFoundException, InvalidDateRangeException;

    ResponseMessage assignDriverToBus(Long busId, String username) throws BusNotFoundException;

    ResponseMessage unassignDriverFromBus(String username);
}
