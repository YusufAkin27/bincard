package akin.city_card.report.service.concretes;

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
import akin.city_card.report.repository.MessageAttachmentRepository;
import akin.city_card.report.repository.ReportMessageRepository;
import akin.city_card.report.repository.ReportPhotoRepository;
import akin.city_card.report.repository.ReportRepository;
import akin.city_card.report.service.abstracts.ReportService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class ReportManager implements ReportService {
    private final ReportRepository reportRepository;
    private final MessageAttachmentRepository messageAttachmentRepository;
    private final ReportPhotoRepository reportPhotoRepository;
    private final ReportMessageRepository repository;

    @Override
    public ResponseMessage createReport(CreateReportRequest request, List<MultipartFile> attachments, String username) throws UserNotFoundException, IOException, PhotoSizeLargerException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException {
        return null;
    }

    @Override
    public ResponseMessage sendMessageByUser(SendMessageRequest request, List<MultipartFile> attachments, String username) throws ReportNotFoundException, UserNotFoundException, IOException, UnauthorizedAreaException, OnlyPhotosAndVideosException, PhotoSizeLargerException, VideoSizeLargerException, FileFormatCouldNotException {
        return null;
    }

    @Override
    public ReportChatDTO getReportChatByUser(Long reportId, String username, Pageable pageable) throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public Page<MessageDTO> getReportMessagesByUser(Long reportId, String username, Pageable pageable) throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public Page<ReportChatDTO> getUserReports(String username, ReportCategory category, ReportStatus status, Pageable pageable) throws UserNotFoundException {
        return null;
    }

    @Override
    public int getUserUnreadCount(String username) throws UserNotFoundException {
        return 0;
    }

    @Override
    public ResponseMessage markAsReadByUser(Long reportId, String username) throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public ResponseMessage deleteReportByUser(Long reportId, String username) throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public UserReportStatsDTO getUserReportStats(String username) throws UserNotFoundException {
        return null;
    }

    @Override
    public ResponseMessage sendMessageByAdmin(SendMessageRequest request, List<MultipartFile> attachments, String username) throws ReportNotFoundException, AdminNotFoundException, IOException, UnauthorizedAreaException, OnlyPhotosAndVideosException, PhotoSizeLargerException, VideoSizeLargerException, FileFormatCouldNotException {
        return null;
    }

    @Override
    public ReportChatDTO getReportChatByAdmin(Long reportId, String username, Pageable pageable) throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public Page<MessageDTO> getReportMessagesByAdmin(Long reportId, String username, Pageable pageable) throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public ResponseMessage markAsReadByAdmin(Long reportId, String username) throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public Page<UnassignedReportDTO> getUnassignedReports(String username, ReportCategory category, ReportPriority priority, Boolean urgent, Pageable pageable) throws AdminNotFoundException {
        return null;
    }

    @Override
    public long getUnassignedReportsCount(String username) throws AdminNotFoundException {
        return 0;
    }

    @Override
    public ResponseMessage assignReportToAdmin(AssignReportRequest request, String currentAdminUsername, String targetAdminUsername) throws AdminNotFoundException, ReportNotFoundException {
        return null;
    }

    @Override
    public ResponseMessage bulkAssignReports(BulkAssignRequest request, String adminUsername) throws AdminNotFoundException, ReportNotFoundException {
        return null;
    }

    @Override
    public ResponseMessage unassignReport(Long reportId, String adminUsername) throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public Page<AdminReportDTO> getAssignedReports(String adminUsername, ReportCategory category, ReportStatus status, ReportPriority priority, Boolean hasUnread, Pageable pageable) throws AdminNotFoundException {
        return null;
    }

    @Override
    public long getAssignedReportsCount(String adminUsername) throws AdminNotFoundException {
        return 0;
    }

    @Override
    public AdminReportDTO getReportDetailForAdmin(Long reportId, String adminUsername) throws ReportNotFoundException, AdminNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public ResponseMessage changeReportStatusByAdmin(Long reportId, ReportStatus status, String adminUsername) throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public ResponseMessage changeReportPriority(Long reportId, ReportPriority priority, String adminUsername) throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public ResponseMessage updateAdminNotes(Long reportId, String notes, String adminUsername) throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public ResponseMessage archiveReportByAdmin(Long reportId, String adminUsername) throws AdminNotFoundException, ReportNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public Page<AdminReportDTO> getAllReportsForSuperAdmin(String superAdminUsername, ReportCategory category, ReportStatus status, ReportPriority priority, Boolean hasUnread, Boolean includeDeleted, String assignedAdminUsername, Pageable pageable) throws AdminNotFoundException {
        return null;
    }

    @Override
    public List<AdminSummaryDTO> getAdminsList(String superAdminUsername) throws AdminNotFoundException {
        return List.of();
    }

    @Override
    public Page<AdminReportDTO> searchReportsForAdmin(String keyword, ReportCategory category, ReportStatus status, ReportPriority priority, String assignedAdminUsername, String adminUsername, Pageable pageable) throws AdminNotFoundException {
        return null;
    }

    @Override
    public ResponseMessage bulkArchiveReports(List<Long> reportIds, String adminUsername) throws AdminNotFoundException, ReportNotFoundException {
        return null;
    }

    @Override
    public ResponseMessage bulkChangeStatus(List<Long> reportIds, ReportStatus newStatus, String adminUsername) throws AdminNotFoundException, ReportNotFoundException {
        return null;
    }

    @Override
    public ResponseMessage bulkChangePriority(List<Long> reportIds, ReportPriority newPriority, String adminUsername) throws AdminNotFoundException, ReportNotFoundException {
        return null;
    }

    @Override
    public ReportStatsDTO getReportStatsForAdmin(String adminUsername) throws AdminNotFoundException {
        return null;
    }

    @Override
    public AdminPerformanceDTO getAdminPerformance(String adminUsername) throws AdminNotFoundException {
        return null;
    }

    @Override
    public Page<AdminPerformanceDTO> getAllAdminPerformances(String superAdminUsername, Pageable pageable) throws AdminNotFoundException {
        return null;
    }

    @Override
    public SatisfactionStatsDTO getSatisfactionStatsForAdmin(String adminUsername) throws AdminNotFoundException {
        return null;
    }

    @Override
    public Page<AdminReportDTO> getDeletedReports(String superAdminUsername, ReportCategory category, ReportStatus status, Pageable pageable) throws AdminNotFoundException {
        return null;
    }

    @Override
    public ResponseMessage restoreReport(Long reportId, String superAdminUsername) throws AdminNotFoundException, ReportNotFoundException {
        return null;
    }

    @Override
    public ResponseMessage editMessage(Long messageId, String username, String newMessage) throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public ResponseMessage deleteMessage(Long messageId, String username) throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException {
        return null;
    }

    @Override
    public ResponseMessage rateSatisfaction(Long reportId, String username, SatisfactionRatingRequest request) throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException, SatisfactionAlreadyRatedException {
        return null;
    }
}
