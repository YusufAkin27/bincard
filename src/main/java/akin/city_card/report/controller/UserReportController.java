package akin.city_card.report.controller;

import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.report.core.request.CreateReportRequest;
import akin.city_card.report.core.request.SatisfactionRatingRequest;
import akin.city_card.report.core.request.SendMessageRequest;
import akin.city_card.report.core.response.MessageDTO;
import akin.city_card.report.core.response.ReportChatDTO;
import akin.city_card.report.core.response.UserReportStatsDTO;
import akin.city_card.report.exceptions.MessageNotFoundException;
import akin.city_card.report.exceptions.ReportNotFoundException;
import akin.city_card.report.exceptions.SatisfactionAlreadyRatedException;
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
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/v1/api/user/report")
@RequiredArgsConstructor
@PreAuthorize("hasRole('USER')")
public class UserReportController {

    private final ReportService reportService;

    // ================== ŞİKAYET OLUŞTURMA ==================

    @PostMapping(value = "/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ResponseMessage> createReport(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("category") ReportCategory category,
            @RequestParam("message") String message,
            @RequestParam(value = "attachments", required = false) List<MultipartFile> attachments)
            throws UserNotFoundException, IOException, OnlyPhotosAndVideosException,
            PhotoSizeLargerException, VideoSizeLargerException, FileFormatCouldNotException {

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

    // ================== MESAJ GÖNDERME ==================

    @PostMapping(value = "/send-message/{reportId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ResponseMessage> sendMessage(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("message") String message,
            @RequestParam(value = "attachments", required = false) List<MultipartFile> attachments)
            throws ReportNotFoundException, UserNotFoundException, IOException, UnauthorizedAreaException,
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

        ResponseMessage response = reportService.sendMessageByUser(request, attachments, userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ================== MESAJ DÜZENLEME/SİLME ==================

    @PutMapping("/edit-message/{messageId}")
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
    public ResponseEntity<ResponseMessage> deleteMessage(
            @PathVariable Long messageId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.deleteMessage(messageId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== ŞİKAYET GÖRÜNTÜLEME ==================

    @GetMapping("/chat/{reportId}")
    public ResponseEntity<ReportChatDTO> getReportChat(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 50, sort = "sentAt", direction = Sort.Direction.ASC) Pageable pageable)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        ReportChatDTO chat = reportService.getReportChatByUser(reportId, userDetails.getUsername(), pageable);
        return ResponseEntity.ok(chat);
    }

    @GetMapping("/chat/{reportId}/messages")
    public ResponseEntity<PageDTO<MessageDTO>> getReportMessages(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20, sort = "sentAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        Page<MessageDTO> messages = reportService.getReportMessagesByUser(reportId, userDetails.getUsername(), pageable);
        return ResponseEntity.ok(new PageDTO<>(messages));
    }

    // ================== ŞİKAYETLERİMİ GÖRÜNTÜLEME ==================

    @GetMapping("/my-reports")
    public ResponseEntity<PageDTO<ReportChatDTO>> getMyReports(
            @RequestParam(required = false) ReportCategory category,
            @RequestParam(required = false) ReportStatus status,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 10, sort = "lastMessageAt", direction = Sort.Direction.DESC) Pageable pageable)
            throws UserNotFoundException {

        Page<ReportChatDTO> reports = reportService.getUserReports(userDetails.getUsername(), category, status, pageable);
        return ResponseEntity.ok(new PageDTO<>(reports));
    }

    @GetMapping("/my-unread-count")
    public ResponseEntity<Integer> getMyUnreadCount(@AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException {

        int unreadCount = reportService.getUserUnreadCount(userDetails.getUsername());
        return ResponseEntity.ok(unreadCount);
    }

    // ================== OKUNDU İŞARETLEME ==================

    @PostMapping("/mark-as-read/{reportId}")
    public ResponseEntity<ResponseMessage> markAsRead(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.markAsReadByUser(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== ŞİKAYET SİLME ==================

    @DeleteMapping("/delete-report/{reportId}")
    public ResponseEntity<ResponseMessage> deleteReport(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        ResponseMessage response = reportService.deleteReportByUser(reportId, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    // ================== MEMNUNİYET PUANLAMA ==================

    @PostMapping("/rate-satisfaction/{reportId}")
    public ResponseEntity<ResponseMessage> rateSatisfaction(
            @PathVariable Long reportId,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody @Valid SatisfactionRatingRequest request)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException,
            SatisfactionAlreadyRatedException {

        ResponseMessage response = reportService.rateSatisfaction(reportId, userDetails.getUsername(), request);
        return ResponseEntity.ok(response);
    }

    // ================== KATEGORİLER ==================

    @GetMapping("/categories")
    public ResponseEntity<ReportCategory[]> getCategories() {
        return ResponseEntity.ok(ReportCategory.values());
    }

    // ================== KULLANICI İSTATİSTİKLERİ ==================

    @GetMapping("/my-stats")
    public ResponseEntity<UserReportStatsDTO> getMyStats(@AuthenticationPrincipal UserDetails userDetails)
            throws UserNotFoundException {

        UserReportStatsDTO stats = reportService.getUserReportStats(userDetails.getUsername());
        return ResponseEntity.ok(stats);
    }
}