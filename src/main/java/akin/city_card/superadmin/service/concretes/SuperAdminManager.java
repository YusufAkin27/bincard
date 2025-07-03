package akin.city_card.superadmin.service.concretes;

import akin.city_card.admin.core.converter.AuditLogConverter;
import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.*;
import akin.city_card.admin.repository.AdminApprovalRequestRepository;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.admin.repository.AuditLogRepository;
import akin.city_card.bus.model.BusRide;
import akin.city_card.bus.model.RideStatus;
import akin.city_card.bus.repository.BusRideRepository;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.SuperAdminNotFoundException;
import akin.city_card.superadmin.exceptions.AdminApprovalRequestNotFoundException;
import akin.city_card.superadmin.exceptions.RequestAlreadyProcessedException;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
import akin.city_card.superadmin.service.abstracts.SuperAdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class SuperAdminManager implements SuperAdminService {
    private final SuperAdminRepository superAdminRepository;
    private final AdminApprovalRequestRepository adminApprovalRequestRepository;
    private final AdminRepository adminRepository;
    private final BusRideRepository busRideRepository;
    private final AuditLogRepository auditLogRepository;
    private final AuditLogConverter auditLogConverter;


    @Override
    public ResponseMessage approveAdminRequest(String username, Long adminId) throws AdminNotFoundException, AdminApprovalRequestNotFoundException, RequestAlreadyProcessedException {
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (superAdmin == null) {
            throw new AdminNotFoundException();
        }
        List<AdminApprovalRequest> adminApprovalRequests = adminApprovalRequestRepository.findAll();
        AdminApprovalRequest request = adminApprovalRequests.stream().filter(adminApprovalRequest -> adminApprovalRequest.getAdmin().getId().equals(adminId)).findFirst().orElseThrow(AdminApprovalRequestNotFoundException::new);

        if (request.getStatus() != ApprovalStatus.PENDING) {
            throw new RequestAlreadyProcessedException();
        }

        request.setStatus(ApprovalStatus.APPROVED);
        request.setUpdateAt(LocalDateTime.now());
        request.setApprovedBy(superAdmin); // varsa
        adminApprovalRequestRepository.save(request);

        Admin admin = request.getAdmin();
        admin.setActive(true);
        adminRepository.save(admin);

        return new ResponseMessage("Admin request approved successfully", true);
    }


    @Override
    public ResponseMessage rejectAdminRequest(String username, Long adminId) throws AdminNotFoundException, RequestAlreadyProcessedException, AdminApprovalRequestNotFoundException {
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (superAdmin == null) {
            throw new AdminNotFoundException();
        }
        List<AdminApprovalRequest> adminApprovalRequests = adminApprovalRequestRepository.findAll();
        AdminApprovalRequest request = adminApprovalRequests.stream().filter(adminApprovalRequest -> adminApprovalRequest.getAdmin().getId().equals(adminId)).findFirst().orElseThrow(AdminApprovalRequestNotFoundException::new);

        if (request.getStatus() != ApprovalStatus.PENDING) {
            throw new RequestAlreadyProcessedException();
        }

        request.setStatus(ApprovalStatus.REJECTED);
        request.setUpdateAt(LocalDateTime.now());
        request.setApprovedBy(superAdmin); // varsa
        adminApprovalRequestRepository.save(request);

        Admin admin = request.getAdmin();
        admin.setActive(false);
        admin.setSuperAdminApproved(false);
        adminRepository.save(admin);
        return new ResponseMessage("Admin request rejected successfully", true);
    }

    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getDailyBusIncome(String username, LocalDate date) {
        LocalDateTime start = date.atStartOfDay();
        LocalDateTime end = date.atTime(23, 59, 59);

        List<BusRide> rides = busRideRepository.findByRideTimeBetweenAndBusDriverUserNumber(start, end, username);

        Map<String, BigDecimal> incomePerBus = new HashMap<>();

        for (BusRide ride : rides) {
            String plate = ride.getBus().getNumberPlate();
            double fare = ride.getBus().calculateFare(ride.getBusCard().getType());
            incomePerBus.merge(plate, BigDecimal.valueOf(fare), BigDecimal::add);
        }

        return new DataResponseMessage<>("başarılı",true,incomePerBus);
    }


    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getWeeklyBusIncome(String username, LocalDate startDate, LocalDate endDate) {
        LocalDateTime start = startDate.atStartOfDay();
        LocalDateTime end = endDate.atTime(23, 59, 59);

        List<BusRide> rides = busRideRepository.findByBoardingTimeBetweenAndBusDriverUserNumberAndStatus(
                start, end, username, RideStatus.SUCCESS);

        Map<String, BigDecimal> incomePerBus = new HashMap<>();

        for (BusRide ride : rides) {
            String plate = ride.getBus().getNumberPlate();
            incomePerBus.merge(plate, ride.getFareCharged(), BigDecimal::add);
        }

        return new DataResponseMessage<>("başarılı",true,incomePerBus);
    }


    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getMonthlyBusIncome(String username, int year, int month) {
        LocalDate startDate = LocalDate.of(year, month, 1);
        LocalDate endDate = startDate.withDayOfMonth(startDate.lengthOfMonth());

        return getWeeklyBusIncome(username, startDate, endDate);
    }


    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getIncomeSummary(String username) {
        List<BusRide> rides = busRideRepository.findByBusDriverUserNumberAndStatus(username, RideStatus.SUCCESS);

        Map<String, BigDecimal> incomePerBus = new HashMap<>();

        for (BusRide ride : rides) {
            String plate = ride.getBus().getNumberPlate();
            incomePerBus.merge(plate, ride.getFareCharged(), BigDecimal::add);
        }

        return new DataResponseMessage<>("başarılı",true,incomePerBus);
    }


    @Override
    public DataResponseMessage<List<AdminApprovalRequest>> getPendingAdminRequest(String username, Pageable pageable) throws SuperAdminNotFoundException {
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (superAdmin == null) {
            throw new SuperAdminNotFoundException();
        }

        Page<AdminApprovalRequest> pendingRequests = adminApprovalRequestRepository
                .findByStatus(ApprovalStatus.PENDING, pageable);

        return new DataResponseMessage<>("başarılı", true, pendingRequests.getContent());
    }

    @Override
    public DataResponseMessage<List<AuditLogDTO>> getAuditLogs(String fromDate, String toDate, String action, String username) {
        LocalDateTime from = (fromDate != null && !fromDate.isBlank()) ?
                LocalDateTime.parse(fromDate) : LocalDateTime.MIN;
        LocalDateTime to = (toDate != null && !toDate.isBlank()) ?
                LocalDateTime.parse(toDate) : LocalDateTime.now();

        ActionType actionType = null;
        if (action != null && !action.isBlank()) {
            try {
                actionType = ActionType.valueOf(action.toUpperCase());
            } catch (IllegalArgumentException e) {
                return new DataResponseMessage<>("başarılı",true,List.of()); // Geçersiz action varsa boş dön
            }
        }

        List<AuditLog> logs;

        if (actionType != null) {
            logs = auditLogRepository.findByUsernameAndActionAndTimestampBetween(username, actionType, from, to);
        } else {
            logs = auditLogRepository.findByUsernameAndTimestampBetween(username, from, to);
        }

        List<AuditLogDTO> dtoList = logs.stream().map(auditLogConverter::mapToDto).toList();
        return new DataResponseMessage<>("başarılı",true,dtoList);
    }



}
