package akin.city_card.superadmin.service.abstracts;

import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.SuperAdminNotFoundException;
import akin.city_card.superadmin.core.request.AddRoleAdminRequest;
import akin.city_card.superadmin.core.request.UpdateAdminRequest;
import akin.city_card.superadmin.core.response.AdminDetailsResponse;
import akin.city_card.superadmin.exceptions.AdminApprovalRequestNotFoundException;
import akin.city_card.superadmin.exceptions.AdminNotActiveException;
import akin.city_card.superadmin.exceptions.RequestAlreadyProcessedException;
import akin.city_card.superadmin.exceptions.ThisTelephoneAlreadyUsedException;
import akin.city_card.user.exceptions.EmailAlreadyExistsException;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetails;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

public interface SuperAdminService {

    ResponseMessage approveAdminRequest(String username, Long requestId) throws AdminNotFoundException, AdminApprovalRequestNotFoundException, RequestAlreadyProcessedException;

    ResponseMessage rejectAdminRequest(String username, Long adminId) throws AdminNotFoundException, RequestAlreadyProcessedException, AdminApprovalRequestNotFoundException;

    DataResponseMessage<Map<String, BigDecimal>> getDailyBusIncome(String username, LocalDate date);

    DataResponseMessage<Map<String, BigDecimal>> getWeeklyBusIncome(String username, LocalDate startDate, LocalDate endDate);

    DataResponseMessage<Map<String, BigDecimal>> getMonthlyBusIncome(String username, int year, int month);

    DataResponseMessage<Map<String, BigDecimal>> getIncomeSummary(String username);

    DataResponseMessage<List<AdminApprovalRequest>> getPendingAdminRequest(String username, Pageable pageable) throws SuperAdminNotFoundException;

    DataResponseMessage<List<AuditLogDTO>> getAuditLogs(String fromDate, String toDate, String action, String username);

    ResponseMessage addRole(String username, AddRoleAdminRequest addRoleAdminRequest) throws AdminNotFoundException, AdminNotActiveException;

    ResponseMessage removeRole(String username, AddRoleAdminRequest addRoleAdminRequest) throws AdminNotFoundException, AdminNotActiveException;

    DataResponseMessage<List<String>> getAdminRoles(UserDetails userDetails, Long adminId) throws AdminNotActiveException, AdminNotFoundException;

    ResponseMessage createAdmin(String username, CreateAdminRequest createAdminRequest) throws ThisTelephoneAlreadyUsedException, EmailAlreadyExistsException;

    ResponseMessage updateAdmin(String username, Long adminId, UpdateAdminRequest updateAdminRequest) throws AdminNotFoundException, AdminNotActiveException, EmailAlreadyExistsException;

    ResponseMessage deleteAdmin(String username, Long adminId) throws AdminNotFoundException;

    ResponseMessage toggleAdminStatus(String username, Long adminId) throws AdminNotFoundException;

    DataResponseMessage<AdminDetailsResponse> getAdminDetails(String username, Long adminId) throws AdminNotFoundException;

    DataResponseMessage<List<AdminDetailsResponse>> getAllAdmins(String username, String status, String role, String searchTerm, Pageable pageable);

    // ===== TOPLU İŞLEMLER =====
    ResponseMessage createBulkAdmins(String username, List<CreateAdminRequest> createRequests);

    ResponseMessage deactivateMultipleAdmins(String username, List<Long> adminIds);

    ResponseMessage activateMultipleAdmins(String username, List<Long> adminIds);

    ResponseMessage assignRolesToMultipleAdmins(String username, Long adminId, List<String> roles);
}
