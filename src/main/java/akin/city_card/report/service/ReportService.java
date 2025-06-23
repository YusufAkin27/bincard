package akin.city_card.report.service;

import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.exceptions.ReportAlreadyDeletedException;
import akin.city_card.report.exceptions.ReportNotActiveException;
import akin.city_card.report.exceptions.ReportNotFoundException;
import akin.city_card.response.ResponseMessage;

public interface ReportService {
    ResponseMessage addReport(AddReportRequest addReportRequest);

    ResponseMessage deleteReport(Long reportId) throws ReportNotFoundException, ReportAlreadyDeletedException, ReportNotActiveException;
}
