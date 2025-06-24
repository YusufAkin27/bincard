package akin.city_card.report.service;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.exceptions.AdminNotFoundExecption;
import akin.city_card.report.exceptions.ReportAlreadyDeletedException;
import akin.city_card.report.exceptions.ReportNotActiveException;
import akin.city_card.report.exceptions.ReportNotFoundException;
import akin.city_card.report.model.Report;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;

import java.util.List;

public interface ReportService {
    ResponseMessage addReport(AddReportRequest addReportRequest);

    ResponseMessage deleteReport(Long reportId) throws ReportNotFoundException, ReportAlreadyDeletedException, ReportNotActiveException;

    List<Report> getAllReport(String username) throws AdminNotFoundExecption, AdminNotFoundException;

    List<Report> getUserReport(String username) throws UserNotFoundException, AdminNotFoundException;
}
