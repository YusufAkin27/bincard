package akin.city_card.report.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.report.core.request.CreateReportRequest;
import akin.city_card.report.core.request.SendMessageRequest;
import akin.city_card.report.core.response.*;
import akin.city_card.report.exceptions.*;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportStatus;
import akin.city_card.report.service.abstracts.ReportService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/v1/api/report")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;

    // ================== CHAT SYSTEM ENDPOINTS ==================

    @PostMapping(value = "/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> createReport(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("category") ReportCategory category,
            @RequestParam("message") String message,
            @RequestParam(value = "attachments", required = false) List<MultipartFile> attachments)
            throws UserNotFoundException, IOException, OnlyPhotosAndVideosException, PhotoSizeLargerException, VideoSizeLargerException, FileFormatCouldNotException {

        if (message == null || message.trim().length() < 10 || message.length() > 1000) {
            return ResponseEntity.badRequest()
                    .body(new ResponseMessage("Mesaj en az 10, en fazla 1000 karakter olmalıdır.", false));
        }

        CreateReportRequest request = CreateReportRequest.builder()
                .category(category)
                .initialMessage(message.trim())
                .build();

        ResponseMessage response = reportService.createReport(request, attachments, userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping(value = "/send-message/{reportId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> sendMessage(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("message") String message,
            @RequestParam(value = "attachments", required = false) List<MultipartFile> attachments)
            throws ReportNotFoundException, UserNotFoundException, IOException, UnauthorizedAreaException, OnlyPhotosAndVideosException, AdminNotFoundException, PhotoSizeLargerException, VideoSizeLargerException, FileFormatCouldNotException {

        if (message == null || message.trim().isEmpty() || message.length() > 1000) {
            return ResponseEntity.badRequest()
                    .body(new ResponseMessage("Mesaj boş olamaz ve 1000 karakteri geçemez.", false));
        }

        SendMessageRequest request = SendMessageRequest.builder()
                .reportId(reportId)
                .message(message.trim())
                .build();

        ResponseMessage response = reportService.sendMessage(request, attachments, userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PutMapping("/edit-message/{messageId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> editMessage(
            @PathVariable Long messageId,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("message") String newMessage)
            throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        if (newMessage == null || newMessage.trim().isEmpty() || newMessage.length() > 1000) {
            return ResponseEntity.badRequest()
                    .body(new ResponseMessage("Mesaj boş olamaz ve 1000 karakteri geçemez.", false));
        }

        ResponseMessage response = reportService.editMessage(messageId, userDetails.getUsername(), newMessage.trim());
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/delete-message/{messageId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> deleteMessage(
            @PathVariable Long messageId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.deleteMessage(messageId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/chat/{reportId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ReportChatDTO> getReportChat(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 50, sort = "sentAt", direction = Sort.Direction.ASC) Pageable pageable)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        ReportChatDTO chat = reportService.getReportChat(reportId, userDetails.getUsername(), pageable);
        return ResponseEntity.ok(chat);
    }

    @GetMapping("/chat/{reportId}/messages")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<PageDTO<MessageDTO>> getReportMessages(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "sentAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        Page<MessageDTO> messages = reportService.getReportMessages(reportId, userDetails.getUsername(), pageable);
        return ResponseEntity.ok(new PageDTO<>(messages));
    }

    @PostMapping("/mark-as-read/{reportId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> markAsRead(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.markAsRead(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== USER ENDPOINTS ==================

    @GetMapping("/my-chats")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<PageDTO<ReportChatDTO>> getMyChats(
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 10, sort = "lastMessageAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws UserNotFoundException {

        Page<ReportChatDTO> chats = reportService.getUserChats(userDetails.getUsername(), category, status, pageable);
        return ResponseEntity.ok(new PageDTO<>(chats));
    }

    @GetMapping("/my-unread-count")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Integer> getMyUnreadCount(@AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException {

        int unreadCount = reportService.getUserUnreadCount(userDetails.getUsername());
        return ResponseEntity.ok(unreadCount);
    }

    @DeleteMapping("/delete-chat/{reportId}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ResponseMessage> deleteChat(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.deleteReportChat(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== ADMIN ENDPOINTS ==================

    @GetMapping("/admin/chats")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<PageDTO<ReportChatDTO>> getAllChats(
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @RequestParam(required = false) Boolean hasUnread,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "lastMessageAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws AdminNotFoundException {

        Page<ReportChatDTO> chats = reportService.getAdminChats(
                userDetails.getUsername(), category, status, hasUnread, pageable);
        return ResponseEntity.ok(new PageDTO<>(chats));
    }

    @GetMapping("/admin/unread-count")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<Integer> getAdminUnreadCount(@AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException {

        int unreadCount = reportService.getAdminUnreadCount(userDetails.getUsername());
        return ResponseEntity.ok(unreadCount);
    }

    @PatchMapping("/admin/change-status/{reportId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> changeReportStatus(
            @PathVariable Long reportId,
            @RequestParam ReportStatus status,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.changeReportStatus(reportId, status, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/admin/archive-chat/{reportId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> archiveChat(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.archiveReportChat(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin/stats")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ReportStatsDTO> getAdminStats(@AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException {

        ReportStatsDTO stats = reportService.getReportStats(userDetails.getUsername());
        return ResponseEntity.ok(stats);
    }

    @PostMapping("/admin/bulk-archive")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> bulkArchiveChats(
            @RequestParam List<Long> reportIds,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.bulkArchiveReports(reportIds, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/admin/bulk-status-change")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> bulkStatusChange(
            @RequestParam List<Long> reportIds,
            @RequestParam ReportStatus newStatus,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.bulkChangeStatus(reportIds, newStatus, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== COMMON ENDPOINTS ==================

    @GetMapping("/categories")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ReportCategory[]> getCategories() {
        return ResponseEntity.ok(ReportCategory.values());
    }

    @GetMapping("/statuses")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ReportStatus[]> getStatuses() {
        return ResponseEntity.ok(ReportStatus.values());
    }

    @PostMapping("/search")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<PageDTO<ReportChatDTO>> searchReports(
            @RequestParam String keyword,
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "lastMessageAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws AdminNotFoundException {

        Page<ReportChatDTO> results = reportService.searchReports(
                keyword, category, status, userDetails.getUsername(), pageable);
        return ResponseEntity.ok(new PageDTO<>(results));
    }


    @PostMapping("/rate-satisfaction/{reportId}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ResponseMessage> rateSatisfaction(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody @Valid SatisfactionRatingRequest request)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException, SatisfactionAlreadyRatedException {

        ResponseMessage response = reportService.rateSatisfaction(reportId, userDetails.getUsername(), request);
        return ResponseEntity.ok(response);
    }

    // Admin için silinmiş sohbetleri görme
    @GetMapping("/admin/deleted-chats")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<PageDTO<ReportChatDTO>> getDeletedChats(
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "lastMessageAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws AdminNotFoundException {

        Page<ReportChatDTO> chats = reportService.getDeletedChats(
                userDetails.getUsername(), category, status, pageable);
        return ResponseEntity.ok(new PageDTO<>(chats));
    }

    // Admin için tüm sohbetleri görme (silinmiş dahil)
    @GetMapping("/admin/all-chats")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<PageDTO<ReportChatDTO>> getAllChatsIncludingDeleted(
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @RequestParam(required = false) Boolean hasUnread,
            @RequestParam(required = false) Boolean includeDeleted,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "lastMessageAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws AdminNotFoundException {

        Page<ReportChatDTO> chats = reportService.getAllAdminChats(
                userDetails.getUsername(), category, status, hasUnread, includeDeleted, pageable);
        return ResponseEntity.ok(new PageDTO<>(chats));
    }

    // Memnuniyet istatistikleri
    @GetMapping("/admin/satisfaction-stats")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<SatisfactionStatsDTO> getSatisfactionStats(
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException {

        SatisfactionStatsDTO stats = reportService.getSatisfactionStats(userDetails.getUsername());
        return ResponseEntity.ok(stats);
    }

    // Belirli bir raporu geri getir (admin için)
    @PatchMapping("/admin/restore-report/{reportId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPERADMIN')")
    public ResponseEntity<ResponseMessage> restoreReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws AdminNotFoundException, ReportNotFoundException {

        ResponseMessage response = reportService.restoreReport(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }
    // ================== HELPER METHODS ==================

    private boolean isAdminOrSuperAdmin(UserDetails userDetails) {
        if (userDetails == null) return false;
        return userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ADMIN") || role.equals("SUPERADMIN"));
    }
}