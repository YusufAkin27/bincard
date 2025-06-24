package akin.city_card.report.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.exceptions.*;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.service.abstracts.ReportService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/v1/api/report")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;

    @PostMapping(value = "/addReport", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseMessage addReport(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("category") ReportCategory category,
            @RequestParam("message") String message,
            @RequestParam(value = "photos", required = false) List<MultipartFile> photos) throws AddReportRequestNullException, UserNotFoundException, PhotoSizeLargerException, IOException {

        AddReportRequest request = AddReportRequest.builder()
                .category(category)
                .message(message)
                .build();

        return reportService.addReport(request, photos, userDetails.getUsername());
    }

    @DeleteMapping("/{reportId}")
    public ResponseMessage deleteReport(@PathVariable Long reportId) throws ReportNotActiveException, ReportNotFoundException, ReportAlreadyDeletedException {
        return reportService.deleteReport(reportId);
    }

    @GetMapping("/getAllReport")
    public List<Report> getAllReport(@AuthenticationPrincipal UserDetails userDetails) throws AdminNotFoundException {
        return reportService.getAllReport(userDetails.getUsername());
    }

    @GetMapping("/getUserReport")
    public List<Report> getUserReport(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, AdminNotFoundException {
        return reportService.getUserReport(userDetails.getUsername());
    }

    @GetMapping("/getReportby/{reportCategory}")
    public  List<Report> getReportByCategory(@PathVariable ReportCategory category, @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, CategoryNotFoundExecption, AdminNotFoundException {
        return  reportService.getReportByCategory(category,userDetails.getUsername());
    }


}
