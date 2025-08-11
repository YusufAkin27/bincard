package akin.city_card.report.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.report.core.request.CreateReportRequest;
import akin.city_card.report.core.request.SendMessageRequest;
import akin.city_card.report.core.response.*;
import akin.city_card.report.exceptions.*;
import akin.city_card.report.model.ReportCategory;
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

    ResponseMessage createReport(CreateReportRequest request, List<MultipartFile> attachments, String username)
            throws UserNotFoundException, IOException, PhotoSizeLargerException, OnlyPhotosAndVideosException,
            VideoSizeLargerException, FileFormatCouldNotException;

    ResponseMessage sendMessage(SendMessageRequest request, List<MultipartFile> attachments, String username)
            throws ReportNotFoundException, UserNotFoundException, IOException, UnauthorizedAreaException,
            PhotoSizeLargerException, OnlyPhotosAndVideosException, VideoSizeLargerException, FileFormatCouldNotException, AdminNotFoundException;

    ResponseMessage editMessage(Long messageId, String username, String newMessage)
            throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    ResponseMessage deleteMessage(Long messageId, String username)
            throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    ReportChatDTO getReportChat(Long reportId, String username, Pageable pageable)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    Page<MessageDTO> getReportMessages(Long reportId, String username, Pageable pageable)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    ResponseMessage markAsRead(Long reportId, String username)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    // User methods
    Page<ReportChatDTO> getUserChats(String username, ReportCategory category, ReportStatus status, Pageable pageable)
            throws UserNotFoundException;

    int getUserUnreadCount(String username)
            throws UserNotFoundException;

    ResponseMessage deleteReportChat(Long reportId, String username)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException;

    // Admin methods
    Page<ReportChatDTO> getAdminChats(String username, ReportCategory category, ReportStatus status,
                                      Boolean hasUnread, Pageable pageable)
            throws AdminNotFoundException;

    int getAdminUnreadCount(String username)
            throws AdminNotFoundException;

    ResponseMessage changeReportStatus(Long reportId, ReportStatus status, String username)
            throws AdminNotFoundException, ReportNotFoundException;

    ResponseMessage archiveReportChat(Long reportId, String username)
            throws AdminNotFoundException, ReportNotFoundException;

    ReportStatsDTO getReportStats(String username)
            throws AdminNotFoundException;

    ResponseMessage bulkArchiveReports(List<Long> reportIds, String username)
            throws AdminNotFoundException, ReportNotFoundException;

    ResponseMessage bulkChangeStatus(List<Long> reportIds, ReportStatus newStatus, String username)
            throws AdminNotFoundException, ReportNotFoundException;

    Page<ReportChatDTO> searchReports(String keyword, ReportCategory category, ReportStatus status,
                                      String username, Pageable pageable)
            throws AdminNotFoundException;

    // Memnuniyet puanı verme
    ResponseMessage rateSatisfaction(Long reportId, String username, SatisfactionRatingRequest request)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException, SatisfactionAlreadyRatedException;

    // Admin için silinmiş sohbetleri görme
    Page<ReportChatDTO> getDeletedChats(String username, ReportCategory category,
                                        ReportStatus status, Pageable pageable)
            throws AdminNotFoundException;

    // Admin için tüm sohbetleri görme (silinmiş dahil)
    Page<ReportChatDTO> getAllAdminChats(String username, ReportCategory category,
                                         ReportStatus status, Boolean hasUnread,
                                         Boolean includeDeleted, Pageable pageable)
            throws AdminNotFoundException;

    // Memnuniyet istatistikleri
    SatisfactionStatsDTO getSatisfactionStats(String username) throws AdminNotFoundException;

    // Raporu geri getir (admin)
    ResponseMessage restoreReport(Long reportId, String username)
            throws AdminNotFoundException, ReportNotFoundException;
}