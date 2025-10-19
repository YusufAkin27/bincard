package akin.city_card.report.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.report.core.request.*;
import akin.city_card.report.core.response.*;
import akin.city_card.report.exceptions.MessageNotFoundException;
import akin.city_card.report.exceptions.ReportNotFoundException;
import akin.city_card.report.exceptions.SatisfactionAlreadyRatedException;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportPriority;
import akin.city_card.report.model.ReportStatus;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public interface ReportService {

    // ================== CORE METHODS ==================
    ResponseMessage createReport(CreateReportRequest request, List<MultipartFile> attachments, String username)
            throws UserNotFoundException, IOException, PhotoSizeLargerException, OnlyPhotosAndVideosException,
            VideoSizeLargerException, FileFormatCouldNotException;

    // ================== USER METHODS ==================
    ResponseMessage sendMessageByUser(SendMessageRequest request, List<MultipartFile> attachments, String username)
            throws ReportNotFoundException, UserNotFoundException, IOException, UnauthorizedAreaException,
            OnlyPhotosAndVideosException, PhotoSizeLargerException, VideoSizeLargerException,
            FileFormatCouldNotException;

    ReportChatDTO getReportChatByUser(Long reportId, String username, Pageable pageable)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    Page<MessageDTO> getReportMessagesByUser(Long reportId, String username, Pageable pageable)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    Page<ReportChatDTO> getUserReports(String username, ReportCategory category, ReportStatus status, Pageable pageable)
            throws UserNotFoundException;

    int getUserUnreadCount(String username) throws UserNotFoundException;

    ResponseMessage markAsReadByUser(Long reportId, String username)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    ResponseMessage deleteReportByUser(Long reportId, String username)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    UserReportStatsDTO getUserReportStats(String username) throws UserNotFoundException;

    // ================== ADMIN METHODS ==================
    ResponseMessage sendMessageByAdmin(SendMessageRequest request, List<MultipartFile> attachments, String username)
            throws ReportNotFoundException, AdminNotFoundException, IOException, UnauthorizedAreaException,
            OnlyPhotosAndVideosException, PhotoSizeLargerException, VideoSizeLargerException,
            FileFormatCouldNotException;

    ReportChatDTO getReportChatByAdmin(Long reportId, String username, Pageable pageable)
            throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException;

    Page<MessageDTO> getReportMessagesByAdmin(Long reportId, String username, Pageable pageable)
            throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException;

    ResponseMessage markAsReadByAdmin(Long reportId, String username)
            throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException;

    // ================== ADMIN ASSIGNMENT METHODS ==================
    Page<UnassignedReportDTO> getUnassignedReports(String username, ReportCategory category, ReportPriority priority,
                                                   Boolean urgent, Pageable pageable) throws AdminNotFoundException;

    long getUnassignedReportsCount(String username) throws AdminNotFoundException;

    ResponseMessage assignReportToAdmin(AssignReportRequest request, String currentAdminUsername, String targetAdminUsername)
            throws AdminNotFoundException, ReportNotFoundException;

    ResponseMessage bulkAssignReports(BulkAssignRequest request, String adminUsername)
            throws AdminNotFoundException, ReportNotFoundException;

    ResponseMessage unassignReport(Long reportId, String adminUsername)
            throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException;

    Page<AdminReportDTO> getAssignedReports(String adminUsername, ReportCategory category, ReportStatus status,
                                            ReportPriority priority, Boolean hasUnread, Pageable pageable)
            throws AdminNotFoundException;

    long getAssignedReportsCount(String adminUsername) throws AdminNotFoundException;

    // ================== ADMIN MANAGEMENT METHODS ==================
    AdminReportDTO getReportDetailForAdmin(Long reportId, String adminUsername)
            throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException;

    ResponseMessage changeReportStatusByAdmin(Long reportId, ReportStatus status, String adminUsername)
            throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException;

    ResponseMessage changeReportPriority(Long reportId, ReportPriority priority, String adminUsername)
            throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException;

    ResponseMessage updateAdminNotes(Long reportId, String notes, String adminUsername)
            throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException;

    ResponseMessage archiveReportByAdmin(Long reportId, String adminUsername)
            throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException;

    // ================== SUPERADMIN METHODS ==================
    Page<AdminReportDTO> getAllReportsForSuperAdmin(String superAdminUsername, ReportCategory category,
                                                    ReportStatus status, ReportPriority priority, Boolean hasUnread,
                                                    Boolean includeDeleted, String assignedAdminUsername, Pageable pageable)
            throws AdminNotFoundException;

    List<AdminSummaryDTO> getAdminsList(String superAdminUsername) throws AdminNotFoundException;

    // ================== SEARCH METHODS ==================
    Page<AdminReportDTO> searchReportsForAdmin(String keyword, ReportCategory category, ReportStatus status,
                                               ReportPriority priority, String assignedAdminUsername,
                                               String adminUsername, Pageable pageable) throws AdminNotFoundException;

    // ================== BULK OPERATIONS ==================
    ResponseMessage bulkArchiveReports(List<Long> reportIds, String adminUsername)
            throws AdminNotFoundException, ReportNotFoundException;

    ResponseMessage bulkChangeStatus(List<Long> reportIds, ReportStatus newStatus, String adminUsername)
            throws AdminNotFoundException, ReportNotFoundException;

    ResponseMessage bulkChangePriority(List<Long> reportIds, ReportPriority newPriority, String adminUsername)
            throws AdminNotFoundException, ReportNotFoundException;

    // ================== STATISTICS METHODS ==================
    ReportStatsDTO getReportStatsForAdmin(String adminUsername) throws AdminNotFoundException;

    AdminPerformanceDTO getAdminPerformance(String adminUsername) throws AdminNotFoundException;

    Page<AdminPerformanceDTO> getAllAdminPerformances(String superAdminUsername, Pageable pageable)
            throws AdminNotFoundException;

    SatisfactionStatsDTO getSatisfactionStatsForAdmin(String adminUsername) throws AdminNotFoundException;

    // ================== DELETED REPORTS METHODS ==================
    Page<AdminReportDTO> getDeletedReports(String superAdminUsername, ReportCategory category,
                                           ReportStatus status, Pageable pageable) throws AdminNotFoundException;

    ResponseMessage restoreReport(Long reportId, String superAdminUsername)
            throws AdminNotFoundException, ReportNotFoundException;

    // ================== COMMON METHODS ==================
    ResponseMessage editMessage(Long messageId, String username, String newMessage)
            throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    ResponseMessage deleteMessage(Long messageId, String username)
            throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    ResponseMessage rateSatisfaction(Long reportId, String username, SatisfactionRatingRequest request)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException, SatisfactionAlreadyRatedException;
}