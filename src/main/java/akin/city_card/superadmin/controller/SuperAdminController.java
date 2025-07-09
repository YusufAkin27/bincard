package akin.city_card.superadmin.controller;

import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.SuperAdminNotFoundException;
import akin.city_card.superadmin.core.response.AdminApprovalRequestDTO;
import akin.city_card.superadmin.exceptions.AdminApprovalRequestNotFoundException;
import akin.city_card.superadmin.exceptions.RequestAlreadyProcessedException;
import akin.city_card.superadmin.service.abstracts.SuperAdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v1/api/superadmin")
@RequiredArgsConstructor
public class SuperAdminController {

    private final SuperAdminService superAdminService;


    @GetMapping("/admin-requests/pending")
    public DataResponseMessage<List<AdminApprovalRequest>> getPendingAdminRequests(
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) throws SuperAdminNotFoundException {
        return superAdminService.getPendingAdminRequest(userDetails.getUsername(), pageable);
    }

    @PostMapping("/admin-requests/{requestId}/approve")
    public ResponseMessage approveAdminRequest(@AuthenticationPrincipal UserDetails userDetails,
                                               @PathVariable Long requestId) throws AdminNotFoundException, AdminApprovalRequestNotFoundException, RequestAlreadyProcessedException {
        return superAdminService.approveAdminRequest(userDetails.getUsername(), requestId);
    }
    @PostMapping("/admin-requests/{adminId}/reject") //Çalışmıyor Managera Bakınız
    public ResponseMessage rejectAdminRequest(@AuthenticationPrincipal UserDetails userDetails,
                                              @PathVariable Long adminId) throws AdminNotFoundException, AdminApprovalRequestNotFoundException, RequestAlreadyProcessedException {
        return superAdminService.rejectAdminRequest(userDetails.getUsername(), adminId);
    }


    // Günlük gelirler
    @GetMapping("/bus-income/daily")
    public DataResponseMessage<Map<String, BigDecimal>> getDailyBusIncome(@AuthenticationPrincipal UserDetails userDetails,
                                                                          @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {
        return superAdminService.getDailyBusIncome(userDetails.getUsername(), date);
    }

    // Haftalık gelir
    @GetMapping("/bus-income/weekly")
    public DataResponseMessage<Map<String, BigDecimal>> getWeeklyBusIncome(@AuthenticationPrincipal UserDetails userDetails,
                                                                           @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
                                                                           @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate) {
        return superAdminService.getWeeklyBusIncome(userDetails.getUsername(), startDate, endDate);
    }

    // Aylık gelir
    @GetMapping("/bus-income/monthly")
    public DataResponseMessage<Map<String, BigDecimal>> getMonthlyBusIncome(@AuthenticationPrincipal UserDetails userDetails,
                                                                            @RequestParam int year,
                                                                            @RequestParam int month) {
        return superAdminService.getMonthlyBusIncome(userDetails.getUsername(), year, month);
    }


    // Günün, haftanın, ayın toplam kazancı
    @GetMapping("/income-summary")
    public DataResponseMessage<Map<String, BigDecimal>> getIncomeSummary(@AuthenticationPrincipal UserDetails userDetails) {
        return superAdminService.getIncomeSummary(userDetails.getUsername());
    }

    //admin log geçmişleri
    @GetMapping("/audit-logs")
    public DataResponseMessage<List<AuditLogDTO>> getAuditLogs(@RequestParam(required = false) String fromDate,
                                                               @RequestParam(required = false) String toDate,
                                                               @RequestParam(required = false) String action,
                                                               @AuthenticationPrincipal UserDetails userDetails) {
        return superAdminService.getAuditLogs(fromDate, toDate, action, userDetails.getUsername());
    }


}
