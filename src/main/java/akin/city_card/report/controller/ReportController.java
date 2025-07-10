package akin.city_card.report.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.core.response.ReportStatsDTO;
import akin.city_card.report.exceptions.*;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportStatus;
import akin.city_card.report.service.abstracts.ReportService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;

import lombok.RequiredArgsConstructor;
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

import org.springframework.data.domain.Pageable;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/v1/api/report")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;

    // ================== USER ENDPOINTS ==================

    @PostMapping(value = "/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> createReport(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("category") ReportCategory category,
            @RequestParam("message") String message,
            @RequestParam(value = "photos", required = false) List<MultipartFile> photos)
            throws AddReportRequestNullException, UserNotFoundException, PhotoSizeLargerException, IOException {

        if (message == null || message.trim().length() < 10 || message.length() > 1000) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Mesaj en az 10, en fazla 1000 karakter olmalıdır.", false));
        }

        AddReportRequest request = AddReportRequest.builder()
                .category(category)
                .message(message.trim())
                .build();

        ResponseMessage response = reportService.addReport(request, photos, userDetails.getUsername());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PutMapping("/{reportId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> updateReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("message") String message)
            throws UserNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.updateReport(reportId, userDetails.getUsername(), message);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{reportId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> deleteReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, ReportNotActiveException, ReportAlreadyDeletedException, UserNotFoundException {

        ResponseMessage response = reportService.deleteReport(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/my-reports")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<List<?>> getMyReports(
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws UserNotFoundException {

        List<?> reports = reportService.getAllReportsForUser(userDetails.getUsername(), pageable);
        return ResponseEntity.ok(reports);
    }

    @GetMapping("/my-reports/category/{category}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<List<?>> getMyReportsByCategory(
            @PathVariable ReportCategory category,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 10) Pageable pageable)
            throws UserNotFoundException {

        List<?> reports = reportService.getReportsByCategoryUser(category, userDetails.getUsername(), pageable);
        return ResponseEntity.ok(reports);
    }

    @GetMapping("/{reportId}/details")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<Object> getReportDetails(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, UserNotFoundException {

        boolean isAdmin = isUserAdmin(userDetails);
        Object report = isAdmin
                ? reportService.getReportByIdAsAdmin(reportId)
                : reportService.getReportByIdAsUser(reportId, userDetails.getUsername());

        return ResponseEntity.ok(report);
    }

    @PostMapping("/reply-to-response/{responseId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> replyToResponse(
            @PathVariable Long responseId,
            @RequestParam("message")  String message,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, UserNotFoundException {

        ResponseMessage response = reportService.replyToReportResponse(responseId, userDetails.getUsername(), message);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/rate-response/{responseId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> rateResponse(
            @PathVariable Long responseId,
            @RequestParam("rating")  int rating,
            @AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.rateResponse(responseId, userDetails.getUsername(), rating);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PutMapping("/update-rating/{ratingId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> updateRating(
            @PathVariable Long ratingId,
            @RequestParam("rating")  int rating,
            @AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException {

        ResponseMessage response = reportService.updateRating(ratingId, userDetails.getUsername(), rating);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/delete-rating/{ratingId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> deleteRating(
            @PathVariable Long ratingId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException {

        ResponseMessage response = reportService.deleteRating(ratingId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/my-responses")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<List<?>> getMyResponses(@AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException {

        List<?> responses = reportService.getAllResponsesByUser(userDetails.getUsername());
        return ResponseEntity.ok(responses);
    }

    // ================== ADMIN ENDPOINTS ==================

    @GetMapping("/admin/all")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<List<?>> getAllReportsForAdmin(
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) throws AdminNotFoundException {

        List<?> reports = reportService.getAllReportsForAdmin(userDetails.getUsername(), pageable);
        return ResponseEntity.ok(reports);
    }

    @GetMapping("/admin/search")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<List<?>> searchReports(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @PageableDefault(size = 20) Pageable pageable) {

        List<?> reports = reportService.search(
                Optional.ofNullable(keyword),
                Optional.ofNullable(category),
                Optional.ofNullable(status),
                pageable
        );
        return ResponseEntity.ok(reports);
    }

    @GetMapping("/admin/category/{category}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<List<?>> getReportsByCategoryAdmin(
            @PathVariable ReportCategory category,
            @PageableDefault(size = 20) Pageable pageable) {

        List<?> reports = reportService.getReportsByCategoryAdmin(category, pageable);
        return ResponseEntity.ok(reports);
    }

    @GetMapping("/admin/status/{status}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<List<?>> getReportsByStatus(
            @PathVariable ReportStatus status,
            @PageableDefault(size = 20) Pageable pageable) {

        List<?> reports = reportService.search(
                Optional.empty(),
                Optional.empty(),
                Optional.of(status),
                pageable
        );
        return ResponseEntity.ok(reports);
    }

    @PatchMapping("/admin/status/{reportId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> changeReportStatus(
            @PathVariable Long reportId,
            @RequestParam ReportStatus status,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.changeStatus(reportId, status, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/admin/reply/{reportId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> replyToReportAsAdmin(
            @PathVariable Long reportId,
            @RequestParam("message")  String message,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, AdminNotFoundException {

        ResponseMessage response = reportService.replyToReportAsAdmin(reportId, userDetails.getUsername(), message);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PatchMapping("/admin/toggle-delete/{reportId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> toggleReportDeletion(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.toggleDeleteReport(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/admin/archive/{reportId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> archiveReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.archiveReport(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/admin/batch-toggle")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> batchToggleReports(
            @RequestParam List<Long> reportIds,
            @RequestParam boolean delete,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, AdminNotFoundException {

        ResponseMessage response = reportService.batchToggleReports(reportIds, delete, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/admin/response/{responseId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> deleteResponseAsAdmin(
            @PathVariable Long responseId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, AdminNotFoundException, UserNotFoundException {

        ResponseMessage response = reportService.deleteResponse(responseId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin/stats")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ReportStatsDTO> getAdminReportStats(@AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException {

        ReportStatsDTO stats = reportService.getReportStats(userDetails.getUsername());
        return ResponseEntity.ok(stats);
    }

    // ================== SUPERADMIN ENDPOINTS ==================

    @GetMapping("/superadmin/all-users-reports")
    @PreAuthorize("hasRole('SUPERADMIN')")
    public ResponseEntity<List<?>> getAllUsersReports(
            @PageableDefault(size = 50, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) throws AdminNotFoundException {

        List<?> reports = reportService.getAllReportsForAdmin("superadmin", pageable);
        return ResponseEntity.ok(reports);
    }

    @PatchMapping("/superadmin/bulk-status-change")
    @PreAuthorize("hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> bulkStatusChange(
            @RequestParam List<Long> reportIds,
            @RequestParam ReportStatus newStatus,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.batchToggleReports(reportIds, false, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== COMMON ENDPOINTS ==================

    @GetMapping("/{reportId}/responses")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<List<?>> getReportResponses(@PathVariable Long reportId)
            throws ReportNotFoundException {

        List<?> responses = reportService.getReportResponses(reportId);
        return ResponseEntity.ok(responses);
    }

    @GetMapping("/categories")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ReportCategory[]> getReportCategories() {
        return ResponseEntity.ok(ReportCategory.values());
    }

    @GetMapping("/statuses")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ReportStatus[]> getReportStatuses() {
        return ResponseEntity.ok(ReportStatus.values());
    }

    // ================== HELPER METHODS ==================

    private boolean isUserAdmin(UserDetails userDetails) {
        return userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN") ||
                        auth.getAuthority().equals("ROLE_SUPERADMIN"));
    }



}