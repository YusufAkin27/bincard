package akin.city_card.report.service;

import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.exceptions.AdminNotFoundExecption;
import akin.city_card.report.exceptions.ReportAlreadyDeletedException;
import akin.city_card.report.exceptions.ReportNotActiveException;
import akin.city_card.report.exceptions.ReportNotFoundException;
import akin.city_card.report.model.Report;
import akin.city_card.report.repository.ReportRepository;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@RequiredArgsConstructor
@Service
public class ReportManager implements ReportService{
    public final ReportRepository reportRepository;
    public final AdminRepository adminRepository;
    @Override
    public ResponseMessage addReport(AddReportRequest addReportRequest) {
        return null;
    }

    @Override
    public ResponseMessage deleteReport(Long reportId) throws ReportNotFoundException, ReportAlreadyDeletedException, ReportNotActiveException {
        Report report = reportRepository.findById(reportId)
                .orElse(null);

        if (report == null) {
            throw new ReportNotFoundException();
        }
        if(report.isDeleted() == true){
            throw new ReportAlreadyDeletedException();
        }
        if(report.isActive() == false){
            throw new ReportNotActiveException();
        }

        report.setDeleted(false);
        reportRepository.save(report);
        return new ResponseMessage("Şikayet başarıyla silindi.", true);
    }

    @Override
    public List<Report> getAllReport(String username) throws AdminNotFoundExecption {
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null){
            throw new AdminNotFoundExecption();
        }
        return reportRepository.findAll();
    }

    @Override
    public List<Report> getUserReport(String username) throws UserNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null){
            throw new UserNotFoundException();
        }
        return reportRepository.findAll();
    }

}
