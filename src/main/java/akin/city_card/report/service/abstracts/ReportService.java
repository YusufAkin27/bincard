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

    ResponseMessage deleteReport(Long reportId,String username) throws ReportNotFoundException, ReportAlreadyDeletedException, ReportNotActiveException;


    List<Report> getUserReport(String username) throws UserNotFoundException, AdminNotFoundException;

    List<Report> getReportByCategory(ReportCategory category, String username) throws UserNotFoundException, CategoryNotFoundExecption, AdminNotFoundException;

    List<AdminReportDTO> getAllReportsForAdmin(String username, Pageable pageable) throws AdminNotFoundException;

    List<UserReportDTO> getAllReportsForUser(String username, Pageable pageable) throws UserNotFoundException;

   List<AdminReportDTO> search(Optional<String> keyword, Optional<ReportCategory> category, Optional<ReportStatus> status, Pageable pageable);

    ResponseMessage updateReport(Long reportId, String username, String message, List<MultipartFile> photos);

    ResponseMessage changeStatus(Long reportId, ReportStatus status, String username);

    ResponseMessage toggleDeleteReport(Long reportId, String username);

    ResponseMessage replyToReportAsAdmin(Long reportId, String username, String message);

    ResponseMessage replyToReportResponse(Long responseId, String username, String message);

    ResponseMessage deleteResponse(Long responseId, String username);

    ResponseMessage rateResponse(Long responseId, String username, int rating);

    ResponseMessage updateRating(Long ratingId, String username, int rating);

    ResponseMessage deleteRating(Long ratingId, String username);

    List<?> getAllResponsesByUser(String username);

    List<?> getReportResponses(Long reportId);

    ResponseMessage batchToggleReports(List<Long> reportIds, boolean delete, String username);

    ResponseMessage archiveReport(Long reportId, String username);

    ReportStatsDTO getReportStats(String username);


    Object getReportByIdAsAdmin(Long reportId);

    Object getReportByIdAsUser(Long reportId, String username);

    List<?> getReportsByCategoryUser(ReportCategory category, String username, Pageable pageable);

    List<?> getReportsByCategoryAdmin(ReportCategory category, Pageable pageable);
}
