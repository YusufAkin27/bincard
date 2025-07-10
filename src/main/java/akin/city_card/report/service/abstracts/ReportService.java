package akin.city_card.report.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.core.response.AdminReportDTO;
import akin.city_card.report.core.response.ReportStatsDTO;
import akin.city_card.report.core.response.UserReportDTO;
import akin.city_card.report.exceptions.*;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportStatus;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import org.springframework.web.multipart.MultipartFile;

import org.springframework.data.domain.Pageable;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

public interface ReportService {
    ResponseMessage addReport(AddReportRequest addReportRequest, List<MultipartFile> photos, String username)
            throws AddReportRequestNullException, UserNotFoundException, PhotoSizeLargerException, IOException;

    ResponseMessage deleteReport(Long reportId,String username) throws ReportNotFoundException, ReportAlreadyDeletedException, ReportNotActiveException, UserNotFoundException;


    List<Report> getReportByCategory(ReportCategory category, String username) throws UserNotFoundException, CategoryNotFoundExecption, AdminNotFoundException;

    List<AdminReportDTO> getAllReportsForAdmin(String username, Pageable pageable) throws AdminNotFoundException;

    List<UserReportDTO> getAllReportsForUser(String username, Pageable pageable) throws UserNotFoundException;

   List<AdminReportDTO> search(Optional<String> keyword, Optional<ReportCategory> category, Optional<ReportStatus> status, Pageable pageable);

    ResponseMessage updateReport(Long reportId, String username, String message) throws ReportNotFoundException, UserNotFoundException;

    ResponseMessage changeStatus(Long reportId, ReportStatus status, String username) throws AdminNotFoundException, ReportNotFoundException;

    ResponseMessage toggleDeleteReport(Long reportId, String username) throws AdminNotFoundException, ReportNotFoundException;

    ResponseMessage replyToReportAsAdmin(Long reportId, String username, String message) throws AdminNotFoundException, ReportNotFoundException;

    ResponseMessage replyToReportResponse(Long responseId, String username, String message) throws ReportNotFoundException, UserNotFoundException;

    ResponseMessage deleteResponse(Long responseId, String username) throws ReportNotFoundException, UserNotFoundException, AdminNotFoundException;

    ResponseMessage rateResponse(Long responseId, String username, int rating) throws UserNotFoundException, ReportNotFoundException;

    ResponseMessage updateRating(Long ratingId, String username, int rating) throws UserNotFoundException;

    ResponseMessage deleteRating(Long ratingId, String username) throws UserNotFoundException;

    List<?> getAllResponsesByUser(String username) throws UserNotFoundException;

    List<?> getReportResponses(Long reportId) throws ReportNotFoundException;

    ResponseMessage batchToggleReports(List<Long> reportIds, boolean delete, String username) throws AdminNotFoundException;

    ResponseMessage archiveReport(Long reportId, String username) throws AdminNotFoundException, ReportNotFoundException;

    ReportStatsDTO getReportStats(String username) throws AdminNotFoundException;


    Object getReportByIdAsAdmin(Long reportId) throws ReportNotFoundException;

    Object getReportByIdAsUser(Long reportId, String username) throws ReportNotFoundException, UserNotFoundException;

    List<?> getReportsByCategoryUser(ReportCategory category, String username, Pageable pageable) throws UserNotFoundException;

    List<?> getReportsByCategoryAdmin(ReportCategory category, Pageable pageable);
}
