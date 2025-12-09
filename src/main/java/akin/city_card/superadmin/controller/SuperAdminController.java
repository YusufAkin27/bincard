package akin.city_card.superadmin.controller;

import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.SuperAdminNotFoundException;
import akin.city_card.superadmin.core.request.AddRoleAdminRequest;
import akin.city_card.superadmin.core.request.BulkRoleAssignmentRequest;
import akin.city_card.superadmin.core.request.UpdateAdminRequest;
import akin.city_card.superadmin.core.response.AdminDetailsResponse;
import akin.city_card.superadmin.exceptions.AdminApprovalRequestNotFoundException;
import akin.city_card.superadmin.exceptions.AdminNotActiveException;
import akin.city_card.superadmin.exceptions.RequestAlreadyProcessedException;
import akin.city_card.superadmin.exceptions.ThisTelephoneAlreadyUsedException;
import akin.city_card.superadmin.service.abstracts.SuperAdminService;
import akin.city_card.user.exceptions.EmailAlreadyExistsException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v1/api/superadmin")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('SUPERADMIN')")
public class SuperAdminController {

    private final SuperAdminService superAdminService;

    @GetMapping("/admin-requests/pending")
    public DataResponseMessage<List<AdminApprovalRequest>> getPendingAdminRequests(
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws SuperAdminNotFoundException {
        return superAdminService.getPendingAdminRequest(userDetails.getUsername(), pageable);
    }

    @PostMapping("/admin-requests/{requestId}/approve")
    public ResponseMessage approveAdminRequest(@AuthenticationPrincipal UserDetails userDetails,
                                               @PathVariable Long requestId)
            throws AdminNotFoundException, AdminApprovalRequestNotFoundException, RequestAlreadyProcessedException {
        return superAdminService.approveAdminRequest(userDetails.getUsername(), requestId);
    }

    @PostMapping("/admin-requests/{adminId}/reject")
    public ResponseMessage rejectAdminRequest(@AuthenticationPrincipal UserDetails userDetails,
                                              @PathVariable Long adminId)
            throws AdminNotFoundException, AdminApprovalRequestNotFoundException, RequestAlreadyProcessedException {
        return superAdminService.rejectAdminRequest(userDetails.getUsername(), adminId);
    }

    @PostMapping("/roles/add")
    public ResponseMessage addRole(@AuthenticationPrincipal UserDetails userDetails,
                                   @RequestBody AddRoleAdminRequest addRoleAdminRequest)
            throws AdminNotFoundException, AdminNotActiveException {
        return superAdminService.addRole(userDetails.getUsername(), addRoleAdminRequest);
    }

    @DeleteMapping("/roles/remove")
    public ResponseMessage removeRole(@AuthenticationPrincipal UserDetails userDetails,
                                      @RequestBody AddRoleAdminRequest addRoleAdminRequest)
            throws AdminNotFoundException, AdminNotActiveException {
        return superAdminService.removeRole(userDetails.getUsername(), addRoleAdminRequest);
    }

    @GetMapping("/roles/{adminId}")
    public DataResponseMessage<List<String>> getRoles(@AuthenticationPrincipal UserDetails userDetails,
                                                      @PathVariable Long adminId)
            throws AdminNotFoundException, AdminNotActiveException {
        return superAdminService.getAdminRoles(userDetails, adminId);
    }

    @GetMapping("/audit-logs")
    public DataResponseMessage<List<AuditLogDTO>> getAuditLogs(
            @RequestParam(required = false) String fromDate,
            @RequestParam(required = false) String toDate,
            @RequestParam(required = false) String action,
            @AuthenticationPrincipal UserDetails userDetails) {
        return superAdminService.getAuditLogs(fromDate, toDate, action, userDetails.getUsername());
    }

    // ===== GELİR RAPORLARI =====

    @GetMapping("/bus-income/daily")
    public DataResponseMessage<Map<String, BigDecimal>> getDailyBusIncome(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {
        return superAdminService.getDailyBusIncome(userDetails.getUsername(), date);
    }

    @GetMapping("/bus-income/weekly")
    public DataResponseMessage<Map<String, BigDecimal>> getWeeklyBusIncome(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate) {
        return superAdminService.getWeeklyBusIncome(userDetails.getUsername(), startDate, endDate);
    }

    @GetMapping("/bus-income/monthly")
    public DataResponseMessage<Map<String, BigDecimal>> getMonthlyBusIncome(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam int year,
            @RequestParam int month) {
        return superAdminService.getMonthlyBusIncome(userDetails.getUsername(), year, month);
    }

    @GetMapping("/income-summary")
    public DataResponseMessage<Map<String, BigDecimal>> getIncomeSummary(
            @AuthenticationPrincipal UserDetails userDetails) {
        return superAdminService.getIncomeSummary(userDetails.getUsername());
    }

    // ===== YENİ ADMIN YÖNETİMİ =====

    @PostMapping("/admins")
    public ResponseMessage createAdmin(@AuthenticationPrincipal UserDetails userDetails,
                                       @RequestBody CreateAdminRequest createAdminRequest) throws ThisTelephoneAlreadyUsedException, EmailAlreadyExistsException {
        return superAdminService.createAdmin(userDetails.getUsername(), createAdminRequest);
    }

    @PutMapping("/admins/{adminId}")
    public ResponseMessage updateAdmin(@AuthenticationPrincipal UserDetails userDetails,
                                       @PathVariable Long adminId,
                                       @RequestBody UpdateAdminRequest updateAdminRequest)
            throws AdminNotFoundException, AdminNotActiveException, EmailAlreadyExistsException {
        return superAdminService.updateAdmin(userDetails.getUsername(), adminId, updateAdminRequest);
    }

    @DeleteMapping("/admins/{adminId}")
    @PreAuthorize("hasAuthority('SUPERADMIN')")
    public ResponseMessage deleteAdmin(@AuthenticationPrincipal UserDetails userDetails,
                                       @PathVariable Long adminId) throws AdminNotFoundException {
        return superAdminService.deleteAdmin(userDetails.getUsername(), adminId);
    }

    @PatchMapping("/admins/{adminId}/toggle-status")
    public ResponseMessage toggleAdminStatus(@AuthenticationPrincipal UserDetails userDetails,
                                             @PathVariable Long adminId) throws AdminNotFoundException {
        return superAdminService.toggleAdminStatus(userDetails.getUsername(), adminId);
    }

    @GetMapping("/admins/{adminId}")
    public DataResponseMessage<AdminDetailsResponse> getAdminDetails(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long adminId) throws AdminNotFoundException {
        return superAdminService.getAdminDetails(userDetails.getUsername(), adminId);
    }

    @GetMapping("/admins")
    public DataResponseMessage<List<AdminDetailsResponse>> getAllAdmins(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String role,
            @RequestParam(required = false) String searchTerm,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return superAdminService.getAllAdmins(userDetails.getUsername(), status, role, searchTerm, pageable);
    }
    // ===== TOPLU İŞLEMLER =====

    @PostMapping("/admins/bulk-create")
    public ResponseMessage createBulkAdmins(@AuthenticationPrincipal UserDetails userDetails,
                                            @RequestBody List<CreateAdminRequest> createRequests) {
        return superAdminService.createBulkAdmins(userDetails.getUsername(), createRequests);
    }

    @PostMapping("/admins/bulk-assign-roles")
    public ResponseMessage assignRolesToMultipleAdmins(@AuthenticationPrincipal UserDetails userDetails,
                                                       @RequestBody BulkRoleAssignmentRequest request) {
        return superAdminService.assignRolesToMultipleAdmins(userDetails.getUsername(), request.getAdminId(), request.getRoles());
    }

    @PostMapping("/admins/bulk-deactivate")
    public ResponseMessage deactivateMultipleAdmins(@AuthenticationPrincipal UserDetails userDetails,
                                                    @RequestBody List<Long> adminIds) {
        return superAdminService.deactivateMultipleAdmins(userDetails.getUsername(), adminIds);
    }

    @PostMapping("/admins/bulk-activate")
    public ResponseMessage activateMultipleAdmins(@AuthenticationPrincipal UserDetails userDetails,
                                                  @RequestBody List<Long> adminIds) {
        return superAdminService.activateMultipleAdmins(userDetails.getUsername(), adminIds);
    }



}

