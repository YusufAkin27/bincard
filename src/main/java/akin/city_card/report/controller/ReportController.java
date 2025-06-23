package akin.city_card.report.controller;

import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.exceptions.ReportAlreadyDeletedException;
import akin.city_card.report.exceptions.ReportNotActiveException;
import akin.city_card.report.exceptions.ReportNotFoundException;
import akin.city_card.report.model.Report;
import akin.city_card.report.service.ReportService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.exceptions.InvalidPhoneNumberFormatException;
import akin.city_card.user.exceptions.PhoneNumberAlreadyExistsException;
import akin.city_card.user.exceptions.PhoneNumberRequiredException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/api/report")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;

    @PostMapping("/addReport")
    public ResponseMessage addReport(@Valid @RequestBody AddReportRequest addReportRequest){
        return reportService.addReport(addReportRequest);
    }
    @DeleteMapping("/{reportId}")
    public ResponseMessage deleteReport(@PathVariable Long reportId) throws ReportNotActiveException, ReportNotFoundException, ReportAlreadyDeletedException {
        return reportService.deleteReport(reportId);
    }


}
