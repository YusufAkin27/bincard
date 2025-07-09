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
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import org.springframework.data.domain.Pageable;


import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/v1/api/report")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;
// çoğu api boş manager'a bakınız
    @PostMapping(value = "/addReport", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseMessage addReport(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("category") ReportCategory category,
            @RequestParam("message") String message,
            @RequestParam(value = "photos", required = false) List<MultipartFile> photos)
            throws AddReportRequestNullException, UserNotFoundException, PhotoSizeLargerException, IOException {
        AddReportRequest request = AddReportRequest.builder()
                .category(category)
                .message(message)
                .build();
        return reportService.addReport(request, photos, userDetails.getUsername());
    }

    @PutMapping("/{reportId}")
    public ResponseMessage updateReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("message") String message
       ) throws UserNotFoundException, ReportNotFoundException {
        return reportService.updateReport(reportId, userDetails.getUsername(), message);
    }

    @DeleteMapping("/{reportId}")
    public ResponseMessage deleteReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, ReportNotActiveException, ReportAlreadyDeletedException {
        return reportService.deleteReport(reportId, userDetails.getUsername());
    }

    @PatchMapping("/admin/status/{reportId}")
    public ResponseMessage changeReportStatus(
            @PathVariable Long reportId,
            @RequestParam ReportStatus status,
            @AuthenticationPrincipal UserDetails userDetails) throws AdminNotFoundException, ReportNotFoundException {
        return reportService.changeStatus(reportId, status, userDetails.getUsername());
    }

    @PatchMapping("/admin/toggleDelete/{reportId}")
    public ResponseMessage toggleReportDeletion(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {
        return reportService.toggleDeleteReport(reportId, userDetails.getUsername());
    }

    @GetMapping("/getAllReport")
    public List<?> getAllReport(
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws AdminNotFoundException, UserNotFoundException {
        String username = userDetails.getUsername();
        boolean isAdmin = userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ADMIN") || auth.getAuthority().equals("SUPERADMIN"));
        return isAdmin
                ? reportService.getAllReportsForAdmin(username, pageable)
                : reportService.getAllReportsForUser(username, pageable);
    }

    @GetMapping("/byCategory")
    public List<?> getReportsByCategory(
            @RequestParam ReportCategory category,//enum string uyuşmazlığı
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 10) Pageable pageable)
            throws AdminNotFoundException, UserNotFoundException {
        String username = userDetails.getUsername();
        boolean isAdmin = userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ADMIN") || auth.getAuthority().equals("SUPERADMIN"));
        return isAdmin
                ? reportService.getReportsByCategoryAdmin(category, pageable)
                : reportService.getReportsByCategoryUser(category, username, pageable);
    }

    @GetMapping("/{reportId}")
    public Object getReportById(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException {
        boolean isAdmin = userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ADMIN") || auth.getAuthority().equals("SUPERADMIN"));
        return isAdmin
                ? reportService.getReportByIdAsAdmin(reportId)
                : reportService.getReportByIdAsUser(reportId, userDetails.getUsername());
    }

    @PostMapping("/admin/reply/{reportId}")
    public ResponseMessage replyToReportAsAdmin(
            @PathVariable Long reportId,
            @RequestParam("message") String message,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, AdminNotFoundException {
        return reportService.replyToReportAsAdmin(reportId, userDetails.getUsername(), message);
    }

    @PostMapping("/replyToResponse/{responseId}")
    public ResponseMessage replyToResponse(
            @PathVariable Long responseId,
            @RequestParam("message") String message,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, UserNotFoundException {
        return reportService.replyToReportResponse(responseId, userDetails.getUsername(), message);
    }

    @DeleteMapping("/response/{responseId}")
    public ResponseMessage deleteResponse(
            @PathVariable Long responseId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException {
        return reportService.deleteResponse(responseId, userDetails.getUsername());
    }

    @PostMapping("/rateResponse/{responseId}")
    public ResponseMessage rateResponse(
            @PathVariable Long responseId,
            @RequestParam("rating") int rating,
            @AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException, ReportNotFoundException {
        return reportService.rateResponse(responseId, userDetails.getUsername(), rating);
    }

    @PutMapping("/rateResponse/{ratingId}")
    public ResponseMessage updateRating(
            @PathVariable Long ratingId,
            @RequestParam("rating") int rating,
            @AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException{
        return reportService.updateRating(ratingId, userDetails.getUsername(), rating);
    }

    @DeleteMapping("/rateResponse/{ratingId}")
    public ResponseMessage deleteRating(
            @PathVariable Long ratingId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException {
        return reportService.deleteRating(ratingId, userDetails.getUsername());
    }

    @GetMapping("/myResponses")
    public List<?> getMyResponses(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return reportService.getAllResponsesByUser(userDetails.getUsername());
    }

    @GetMapping("/{reportId}/responses")
    public List<?> getReportResponses(@PathVariable Long reportId) throws ReportNotFoundException {
        return reportService.getReportResponses(reportId);
    }

    @DeleteMapping("/admin/batchToggle")
    public ResponseMessage batchToggleReports(
            @RequestParam List<Long> reportIds,
            @RequestParam boolean delete,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, AdminNotFoundException {
        return reportService.batchToggleReports(reportIds, delete, userDetails.getUsername());
    }

    @PatchMapping("/admin/archive/{reportId}")
    public ResponseMessage archiveReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {
        return reportService.archiveReport(reportId, userDetails.getUsername());
    }

    @GetMapping("/admin/stats")
    public ReportStatsDTO getAdminReportStats(@AuthenticationPrincipal UserDetails userDetails) throws AdminNotFoundException {
        return reportService.getReportStats(userDetails.getUsername());
    }


}

