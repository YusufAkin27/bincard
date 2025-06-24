package akin.city_card.report.service;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.exceptions.*;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportPhoto;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

public interface ReportService {
    ResponseMessage addReport(AddReportRequest addReportRequest, String userDetails) throws AddReportRequestNullException, UserNotFoundException;

    ResponseMessage deleteReport(Long reportId) throws ReportNotFoundException, ReportAlreadyDeletedException, ReportNotActiveException;

    List<Report> getAllReport(String username) throws AdminNotFoundException;

    List<Report> getUserReport(String username) throws UserNotFoundException, AdminNotFoundException;

    List<Report> getReportByCategory(ReportCategory category, String username) throws UserNotFoundException, CategoryNotFoundExecption, AdminNotFoundException;
}
