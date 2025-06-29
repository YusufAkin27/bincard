package akin.city_card.superadmin.controller;

import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.superadmin.service.abstracts.SuperAdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
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
public class SuperAdminController {

    private final SuperAdminService superAdminService;

    // Tüm onay bekleyen admin isteklerini getir
    @GetMapping("/admin-requests/pending")
    public DataResponseMessage<List<AdminApprovalRequest>> getPendingAdminRequests(@AuthenticationPrincipal UserDetails userDetails) {
        return superAdminService.getPendingAdminRequest(userDetails.getUsername());
    }

    // Admin isteğini onayla
    @PostMapping("/admin-requests/{adminId}/approve")
    public ResponseMessage approveAdminRequest(@AuthenticationPrincipal UserDetails userDetails,
                                               @PathVariable Long adminId) {
        return superAdminService.approveAdminRequest(userDetails.getUsername(), adminId);
    }

    // Admin isteğini reddet (soft delete)
    @PostMapping("/admin-requests/{adminId}/reject")
    public ResponseMessage rejectAdminRequest(@AuthenticationPrincipal UserDetails userDetails,
                                              @PathVariable Long adminId) {
        return superAdminService.rejectAdminRequest(userDetails.getUsername(), adminId);
    }

    // --- OTOMOBİS GELİR İSTATİSTİKLERİ ---

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
}
