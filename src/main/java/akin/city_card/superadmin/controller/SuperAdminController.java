package akin.city_card.superadmin.controller;

import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.SuperAdminNotFoundException;
import akin.city_card.superadmin.core.request.AddRoleAdminRequest;
import akin.city_card.superadmin.core.request.UpdateAdminRequest;
import akin.city_card.superadmin.exceptions.AdminApprovalRequestNotFoundException;
import akin.city_card.superadmin.exceptions.AdminNotActiveException;
import akin.city_card.superadmin.exceptions.RequestAlreadyProcessedException;
import akin.city_card.superadmin.exceptions.ThisTelephoneAlreadyUsedException;
import akin.city_card.superadmin.service.abstracts.SuperAdminService;
import akin.city_card.user.core.response.Views;
import akin.city_card.user.exceptions.EmailAlreadyExistsException;
import com.fasterxml.jackson.annotation.JsonView;
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
    @JsonView(Views.SuperAdmin.class)
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
    public ResponseMessage deleteAdmin(@AuthenticationPrincipal UserDetails userDetails,
                                       @PathVariable Long adminId) throws AdminNotFoundException {
        return superAdminService.deleteAdmin(userDetails.getUsername(), adminId);
    }

    @PatchMapping("/admins/{adminId}/toggle-status")
    public ResponseMessage toggleAdminStatus(@AuthenticationPrincipal UserDetails userDetails,
                                             @PathVariable Long adminId) throws AdminNotFoundException {
        return superAdminService.toggleAdminStatus(userDetails.getUsername(), adminId);
    }
/*
    @GetMapping("/admins/{adminId}")
    public DataResponseMessage<AdminDetailsResponse> getAdminDetails(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long adminId) throws AdminNotFoundException {
        return superAdminService.getAdminDetails(userDetails.getUsername(), adminId);
    }

    @GetMapping("/admins")
    public DataResponseMessage<List<AdminListResponse>> getAllAdmins(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String role,
            @RequestParam(required = false) String searchTerm,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return superAdminService.getAllAdmins(userDetails.getUsername(), status, role, searchTerm, pageable);
    }

    @PostMapping("/admins/{adminId}/reset-password")
    public ResponseMessage resetAdminPassword(@AuthenticationPrincipal UserDetails userDetails,
                                              @PathVariable Long adminId) throws AdminNotFoundException {
        return superAdminService.resetAdminPassword(userDetails.getUsername(), adminId);
    }

    @PostMapping("/admins/{adminId}/terminate-session")
    public ResponseMessage terminateAdminSessions(@AuthenticationPrincipal UserDetails userDetails,
                                                  @PathVariable Long adminId) throws AdminNotFoundException {
        return superAdminService.terminateAdminSessions(userDetails.getUsername(), adminId);
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
        return superAdminService.assignRolesToMultipleAdmins(userDetails.getUsername(),
                request.getAdminIds(), request.getRoles());
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

    // ===== SİSTEM YÖNETİMİ =====

    @GetMapping("/system/statistics")
    public DataResponseMessage<SystemStatsResponse> getSystemStatistics(
            @AuthenticationPrincipal UserDetails userDetails) {
        return superAdminService.getSystemStatistics(userDetails.getUsername());
    }

    @PutMapping("/system/config")
    public ResponseMessage updateSystemConfig(@AuthenticationPrincipal UserDetails userDetails,
                                              @RequestBody SystemConfigRequest configRequest) {
        return superAdminService.updateSystemConfig(userDetails.getUsername(), configRequest);
    }

    @PostMapping("/system/maintenance")
    public ResponseMessage toggleMaintenanceMode(@AuthenticationPrincipal UserDetails userDetails,
                                                 @RequestParam boolean enabled,
                                                 @RequestParam(required = false) String reason) {
        return superAdminService.toggleMaintenanceMode(userDetails.getUsername(), enabled, reason);
    }

    @PostMapping("/system/cache/clear")
    public ResponseMessage clearSystemCache(@AuthenticationPrincipal UserDetails userDetails,
                                            @RequestParam String cacheType) {
        return superAdminService.clearSystemCache(userDetails.getUsername(), cacheType);
    }

    @PostMapping("/system/backup")
    public ResponseMessage triggerDatabaseBackup(@AuthenticationPrincipal UserDetails userDetails) {
        return superAdminService.triggerDatabaseBackup(userDetails.getUsername());
    }

    @GetMapping("/system/health")
    public DataResponseMessage<Map<String, Object>> getSystemHealth(
            @AuthenticationPrincipal UserDetails userDetails) {
        return superAdminService.getSystemHealth(userDetails.getUsername());
    }

    @GetMapping("/system/performance")
    public DataResponseMessage<Map<String, Object>> getPerformanceMetrics(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "24h") String timeframe) {
        return superAdminService.getPerformanceMetrics(userDetails.getUsername(), timeframe);
    }




    @GetMapping("/reports/admin-activity/{adminId}")
    public DataResponseMessage<List<Object>> getAdminActivityReport(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long adminId,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate) {
        return superAdminService.getAdminActivityReport(userDetails.getUsername(), adminId, startDate, endDate);
    }

    @GetMapping("/reports/revenue")
    public DataResponseMessage<Map<String, Object>> getRevenueAnalysis(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam String period,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate) {
        return superAdminService.getRevenueAnalysis(userDetails.getUsername(), period, startDate, endDate);
    }

    @GetMapping("/analytics/user-behavior")
    public DataResponseMessage<Map<String, Object>> getUserBehaviorAnalysis(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "30d") String timeframe) {
        return superAdminService.getUserBehaviorAnalysis(userDetails.getUsername(), timeframe);
    }

    @GetMapping("/analytics/capacity")
    public DataResponseMessage<Map<String, Object>> getCapacityAnalysis(
            @AuthenticationPrincipal UserDetails userDetails) {
        return superAdminService.getCapacityAnalysis(userDetails.getUsername());
    }

    // ===== GÜVENLİK YÖNETİMİ =====

    @GetMapping("/security/logs")
    public DataResponseMessage<List<Object>> getSecurityLogs(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate,
            @PageableDefault(size = 50) Pageable pageable) {
        return superAdminService.getSecurityLogs(userDetails.getUsername(), severity, startDate, endDate, pageable);
    }

    @GetMapping("/security/suspicious-activities")
    public DataResponseMessage<List<Object>> getSuspiciousActivities(
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20) Pageable pageable) {
        return superAdminService.getSuspiciousActivities(userDetails.getUsername(), pageable);
    }

    @PostMapping("/security/alerts/configure")
    public ResponseMessage configureSecurityAlerts(@AuthenticationPrincipal UserDetails userDetails,
                                                   @RequestBody Map<String, Object> alertConfig) {
        return superAdminService.configureSecurityAlerts(userDetails.getUsername(), alertConfig);
    }

    @GetMapping("/logs/errors")
    public DataResponseMessage<List<Object>> analyzeErrorLogs(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate,
            @RequestParam(required = false) String severity) {
        return superAdminService.analyzeErrorLogs(userDetails.getUsername(), startDate, endDate, severity);
    }


 */

}

