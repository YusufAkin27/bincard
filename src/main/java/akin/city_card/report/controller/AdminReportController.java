package akin.city_card.report.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.report.core.request.AssignReportRequest;
import akin.city_card.report.core.request.BulkAssignRequest;
import akin.city_card.report.core.request.SendMessageRequest;
import akin.city_card.report.core.response.*;
import akin.city_card.report.exceptions.ReportNotFoundException;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportPriority;
import akin.city_card.report.model.ReportStatus;
import akin.city_card.report.service.abstracts.ReportService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/v1/api/admin/report")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('REPORT_ADMIN') or hasAuthority('SUPERADMIN')")
public class AdminReportController {

    private final ReportService reportService;

    // ================== ATANMAMIŞ ŞİKAYETLER ==================

    @GetMapping("/unassigned")
    public ResponseEntity<PageDTO<UnassignedReportDTO>> getUnassignedReports(
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportPriority priority,
            @RequestParam(required = false) Boolean urgent,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.ASC) Pageable pageable)
            throws AdminNotFoundException {

        Page<UnassignedReportDTO> reports = reportService.getUnassignedReports(
                userDetails.getUsername(), category, priority, urgent, pageable);
        return ResponseEntity.ok(new PageDTO<>(reports));
    }

    @GetMapping("/unassigned/count")
    public ResponseEntity<Long> getUnassignedReportsCount(@AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException {

        long count = reportService.getUnassignedReportsCount(userDetails.getUsername());
        return ResponseEntity.ok(count);
    }

    // ================== ŞİKAYET ATAMA ==================

    @PostMapping("/assign")
    public ResponseEntity<ResponseMessage> assignReportToSelf(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody @Valid AssignReportRequest request)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.assignReportToAdmin(
                request, userDetails.getUsername(), userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/assign-to-admin")
    @PreAuthorize("hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> assignReportToAdmin(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody @Valid AssignReportRequest request,
            @RequestParam String targetAdminUsername)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.assignReportToAdmin(
                request, userDetails.getUsername(), targetAdminUsername);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/bulk-assign")
    public ResponseEntity<ResponseMessage> bulkAssignReports(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody @Valid BulkAssignRequest request)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.bulkAssignReports(request, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/unassign/{reportId}")
    public ResponseEntity<ResponseMessage> unassignReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.unassignReport(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== ATANAN ŞİKAYETLER ==================

    @GetMapping("/my-assigned")
    public ResponseEntity<PageDTO<AdminReportDTO>> getMyAssignedReports(
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @RequestParam(required = false) ReportPriority priority,
            @RequestParam(required = false) Boolean hasUnread,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "lastMessageAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws AdminNotFoundException {

        Page<AdminReportDTO> reports = reportService.getAssignedReports(
                userDetails.getUsername(), category, status, priority, hasUnread, pageable);
        return ResponseEntity.ok(new PageDTO<>(reports));
    }

    @GetMapping("/my-assigned/count")
    public ResponseEntity<Long> getMyAssignedReportsCount(@AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException {

        long count = reportService.getAssignedReportsCount(userDetails.getUsername());
        return ResponseEntity.ok(count);
    }

    // ================== TÜM ŞİKAYETLER (SUPERADMIN) ==================

    @GetMapping("/all")
    @PreAuthorize("hasRole('SUPERADMIN')")
    public ResponseEntity<PageDTO<AdminReportDTO>> getAllReports(
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @RequestParam(required = false) ReportPriority priority,
            @RequestParam(required = false) Boolean hasUnread,
            @RequestParam(required = false) Boolean includeDeleted,
            @RequestParam(required = false) String assignedAdminUsername,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "lastMessageAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws AdminNotFoundException {

        Page<AdminReportDTO> reports = reportService.getAllReportsForSuperAdmin(
                userDetails.getUsername(), category, status, priority, hasUnread,
                includeDeleted, assignedAdminUsername, pageable);
        return ResponseEntity.ok(new PageDTO<>(reports));
    }

    // ================== MESAJ GÖNDERME ==================

    @PostMapping(value = "/send-message/{reportId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ResponseMessage> sendMessage(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("message") String message,
            @RequestParam(value = "attachments", required = false) List<MultipartFile> attachments)
            throws ReportNotFoundException, AdminNotFoundException, IOException, UnauthorizedAreaException,
            OnlyPhotosAndVideosException, PhotoSizeLargerException, VideoSizeLargerException,
            FileFormatCouldNotException {

        if (message == null || message.trim().isEmpty() || message.length() > 1000) {
            return ResponseEntity.badRequest()
                    .body(new ResponseMessage("Mesaj boş olamaz ve 1000 karakteri geçemez.", false));
        }

        SendMessageRequest request = SendMessageRequest.builder()
                .reportId(reportId)
                .message(message.trim())
                .build();

        ResponseMessage response = reportService.sendMessageByAdmin(request, attachments, userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ================== ŞİKAYET DETAYI ==================

    @GetMapping("/detail/{reportId}")
    public ResponseEntity<AdminReportDTO> getReportDetail(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException {

        AdminReportDTO report = reportService.getReportDetailForAdmin(reportId, userDetails.getUsername());
        return ResponseEntity.ok(report);
    }

    @GetMapping("/chat/{reportId}")
    public ResponseEntity<ReportChatDTO> getReportChat(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 50, sort = "sentAt", direction = Sort.Direction.ASC) Pageable pageable)
            throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException {

        ReportChatDTO chat = reportService.getReportChatByAdmin(reportId, userDetails.getUsername(), pageable);
        return ResponseEntity.ok(chat);
    }

    @GetMapping("/chat/{reportId}/messages")
    public ResponseEntity<PageDTO<MessageDTO>> getReportMessages(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "sentAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException {

        Page<MessageDTO> messages = reportService.getReportMessagesByAdmin(reportId, userDetails.getUsername(), pageable);
        return ResponseEntity.ok(new PageDTO<>(messages));
    }

    // ================== ŞİKAYET YÖNETİMİ ==================

    @PatchMapping("/change-status/{reportId}")
    public ResponseEntity<ResponseMessage> changeReportStatus(
            @PathVariable Long reportId,
            @RequestParam ReportStatus status,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.changeReportStatusByAdmin(reportId, status, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/change-priority/{reportId}")
    public ResponseEntity<ResponseMessage> changeReportPriority(
            @PathVariable Long reportId,
            @RequestParam ReportPriority priority,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.changeReportPriority(reportId, priority, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PutMapping("/update-notes/{reportId}")
    public ResponseEntity<ResponseMessage> updateAdminNotes(
            @PathVariable Long reportId,
            @RequestParam("notes") String notes,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.updateAdminNotes(reportId, notes, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/archive/{reportId}")
    public ResponseEntity<ResponseMessage> archiveReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.archiveReportByAdmin(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== OKUNDU İŞARETLEME ==================

    @PostMapping("/mark-as-read/{reportId}")
    public ResponseEntity<ResponseMessage> markAsRead(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.markAsReadByAdmin(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== TOPLU İŞLEMLER ==================

    @PostMapping("/bulk-archive")
    public ResponseEntity<ResponseMessage> bulkArchiveReports(
            @RequestParam List<Long> reportIds,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.bulkArchiveReports(reportIds, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/bulk-status-change")
    public ResponseEntity<ResponseMessage> bulkStatusChange(
            @RequestParam List<Long> reportIds,
            @RequestParam ReportStatus newStatus,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.bulkChangeStatus(reportIds, newStatus, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/bulk-priority-change")
    public ResponseEntity<ResponseMessage> bulkPriorityChange(
            @RequestParam List<Long> reportIds,
            @RequestParam ReportPriority newPriority,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.bulkChangePriority(reportIds, newPriority, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== ARAMA ==================

    @PostMapping("/search")
    public ResponseEntity<PageDTO<AdminReportDTO>> searchReports(
            @RequestParam String keyword,
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @RequestParam(required = false) ReportPriority priority,
            @RequestParam(required = false) String assignedAdminUsername,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "lastMessageAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws AdminNotFoundException {

        Page<AdminReportDTO> results = reportService.searchReportsForAdmin(
                keyword, category, status, priority, assignedAdminUsername, userDetails.getUsername(), pageable);
        return ResponseEntity.ok(new PageDTO<>(results));
    }

    // ================== İSTATİSTİKLER ==================

    @GetMapping("/stats")
    public ResponseEntity<ReportStatsDTO> getReportStats(@AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException {

        ReportStatsDTO stats = reportService.getReportStatsForAdmin(userDetails.getUsername());
        return ResponseEntity.ok(stats);
    }

    @GetMapping("/my-performance")
    public ResponseEntity<AdminPerformanceDTO> getMyPerformance(@AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException {

        AdminPerformanceDTO performance = reportService.getAdminPerformance(userDetails.getUsername());
        return ResponseEntity.ok(performance);
    }

    @GetMapping("/admin-performances")
    @PreAuthorize("hasRole('SUPERADMIN')")
    public ResponseEntity<PageDTO<AdminPerformanceDTO>> getAllAdminPerformances(
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "totalAssignedReports", direction = Sort.Direction.DESC) Pageable pageable)
            throws AdminNotFoundException {

        Page<AdminPerformanceDTO> performances = reportService.getAllAdminPerformances(userDetails.getUsername(), pageable);
        return ResponseEntity.ok(new PageDTO<>(performances));
    }

    @GetMapping("/satisfaction-stats")
    public ResponseEntity<SatisfactionStatsDTO> getSatisfactionStats(
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException {

        SatisfactionStatsDTO stats = reportService.getSatisfactionStatsForAdmin(userDetails.getUsername());
        return ResponseEntity.ok(stats);
    }

    // ================== SİLİNMİŞ ŞİKAYETLER ==================

    @GetMapping("/deleted")
    @PreAuthorize("hasRole('SUPERADMIN')")
    public ResponseEntity<PageDTO<AdminReportDTO>> getDeletedReports(
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "lastMessageAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws AdminNotFoundException {

        Page<AdminReportDTO> reports = reportService.getDeletedReports(userDetails.getUsername(), category, status, pageable);
        return ResponseEntity.ok(new PageDTO<>(reports));
    }

    @PatchMapping("/restore/{reportId}")
    @PreAuthorize("hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> restoreReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.restoreReport(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== SABIT DEĞERLER ==================

    @GetMapping("/categories")
    public ResponseEntity<ReportCategory[]> getCategories() {
        return ResponseEntity.ok(ReportCategory.values());
    }

    @GetMapping("/statuses")
    public ResponseEntity<ReportStatus[]> getStatuses() {
        return ResponseEntity.ok(ReportStatus.values());
    }

    @GetMapping("/priorities")
    public ResponseEntity<ReportPriority[]> getPriorities() {
        return ResponseEntity.ok(ReportPriority.values());
    }

    // ================== ADMIN LİSTESİ (SUPERADMIN) ==================

    @GetMapping("/admins")
    @PreAuthorize("hasRole('SUPERADMIN')")
    public ResponseEntity<List<AdminSummaryDTO>> getAdminsList(@AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException {

        List<AdminSummaryDTO> admins = reportService.getAdminsList(userDetails.getUsername());
        return ResponseEntity.ok(admins);
    }
}