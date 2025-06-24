package akin.city_card.report.service.concretes;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.exceptions.*;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportPhoto;
import akin.city_card.report.model.ReportStatus;
import akin.city_card.report.repository.ReportRepository;
import akin.city_card.report.service.abstracts.ReportService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@RequiredArgsConstructor
@Service
public class ReportManager implements ReportService {

    public final ReportRepository reportRepository;
    public final AdminRepository adminRepository;
    public final UserRepository userRepository;
    private final MediaUploadService mediaUploadService;

    @Override
    public ResponseMessage addReport(AddReportRequest addReportRequest, List<MultipartFile> photos, String username)
            throws AddReportRequestNullException, UserNotFoundException, PhotoSizeLargerException, IOException {

        if (addReportRequest == null) {
            throw new AddReportRequestNullException();
        }

        User user = userRepository.findByUserNumber(username);
        if (user == null) {
            throw new UserNotFoundException();
        }

        List<ReportPhoto> reportPhotos = new ArrayList<>();

        if (photos != null && !photos.isEmpty()) {
            for (MultipartFile photo : photos) {
                String photoUrl = String.valueOf(mediaUploadService.uploadAndOptimizeImage(photo));
                ReportPhoto reportPhoto = new ReportPhoto();
                reportPhoto.setImageUrl(photoUrl);
                reportPhoto.setUploadedAt(LocalDateTime.now());
                reportPhoto.setReport(null); // İlişki daha sonra kurulabilir
                reportPhotos.add(reportPhoto);
            }
        }

        Report report = new Report();
        report.setUser(user);
        report.setCategory(addReportRequest.getCategory());
        report.setMessage(addReportRequest.getMessage());
        report.setPhotos(reportPhotos);
        report.setStatus(ReportStatus.OPEN);
        report.setCreatedAt(LocalDateTime.now());
        report.setUpdatedAt(LocalDateTime.now());
        report.setDeleted(false);
        report.setActive(true);

        reportRepository.save(report);

        return new ResponseMessage("Rapor başarıyla oluşturuldu", true);
    }


    @Override
    public ResponseMessage deleteReport(Long reportId) throws ReportNotFoundException, ReportAlreadyDeletedException, ReportNotActiveException {
        Report report = reportRepository.findById(reportId)
                .orElse(null);

        if (report == null) {
            throw new ReportNotFoundException();
        }
        if (report.isDeleted()) {
            throw new ReportAlreadyDeletedException();
        }
        if (!report.isActive()) {
            throw new ReportNotActiveException();
        }

        report.setDeleted(false);
        reportRepository.save(report);
        return new ResponseMessage("Şikayet başarıyla silindi.", true);
    }

    @Override
    public List<Report> getAllReport(String username) throws AdminNotFoundException {

        return reportRepository.findAll();
    }

    @Override
    public List<Report> getUserReport(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);
        if (user == null) {
            throw new UserNotFoundException();
        }
        return reportRepository.findByUser(user);
    }

    @Override
    public List<Report> getReportByCategory(ReportCategory category, String username) throws UserNotFoundException, CategoryNotFoundExecption, AdminNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        User user = userRepository.findByUserNumber(username);
        if (admin != null) {
            return reportRepository.findAllByCategory(category);
        } else if (user == null) {
            throw new UserNotFoundException();
        }
        if (category == null) {
            throw new CategoryNotFoundExecption();
        }
        return reportRepository.findAllByCategoryAndUser(category, user);
    }

}
