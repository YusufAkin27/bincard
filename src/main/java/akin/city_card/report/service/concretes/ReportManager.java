package akin.city_card.report.service.concretes;


import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.report.core.converter.ReportConverter;
import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.core.response.AdminReportDTO;
import akin.city_card.report.core.response.ReportStatsDTO;
import akin.city_card.report.core.response.UserReportDTO;
import akin.city_card.report.exceptions.*;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportCategory;
import akin.city_card.report.model.ReportPhoto;
import akin.city_card.report.model.ReportStatus;
import akin.city_card.report.repository.ReportRepository;
import akin.city_card.report.service.abstracts.ReportService;
import akin.city_card.report.service.abstracts.ReportSpecification;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class ReportManager implements ReportService {

    public final ReportRepository reportRepository;
    public final AdminRepository adminRepository;
    public final UserRepository userRepository;
    private final MediaUploadService mediaUploadService;

    private final ReportConverter reportConverter;

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
                reportPhoto.setReport(null);
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
    public ResponseMessage deleteReport(Long reportId, String username) throws ReportNotFoundException, ReportAlreadyDeletedException, ReportNotActiveException {
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
    public List<Report> getReportByCategory(ReportCategory category, String username) throws UserNotFoundException, CategoryNotFoundExecption, AdminNotFoundException, AdminNotFoundException {
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

    @Override
    public List<AdminReportDTO> getAllReportsForAdmin(String adminUsername, Pageable pageable) {
        return reportRepository.findAll(pageable)
                .stream()
                .map(reportConverter::convertToAdminReportDTO)
                .collect(Collectors.toList());
    }

    public User findByUserName(String userName) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(userName);
        if (user == null) {
            throw new UserNotFoundException();
        }
        return user;
    }

    @Override
    public List<UserReportDTO> getAllReportsForUser(String username, Pageable pageable) throws UserNotFoundException {
        User user = findByUserName(username);
        return reportRepository.findByUser(user, pageable)
                .stream()
                .map(reportConverter::convertToUserReportDTO)
                .collect(Collectors.toList());
    }


    @Override
    public List<AdminReportDTO> search(Optional<String> keyword, Optional<ReportCategory> category, Optional<ReportStatus> status, Pageable pageable) {
        Specification<Report> spec = (root, query, cb) -> cb.conjunction(); // boş filtre başlangıcı

        if (category.isPresent()) {
            spec = spec.and(ReportSpecification.hasCategory(category.get()));
        }

        if (status.isPresent()) {
            spec = spec.and(ReportSpecification.hasStatus(status.get()));
        }

        if (keyword.isPresent()) {
            spec = spec.and(ReportSpecification.containsKeyword(keyword.get()));
        }

        Page<Report> reportPage = reportRepository.findAll(spec, pageable);

        return reportPage.stream()
                .map(reportConverter::convertToAdminReportDTO)
                .collect(Collectors.toList());
    }

    @Override
    public ResponseMessage updateReport(Long reportId, String username, String message) throws ReportNotFoundException, UserNotFoundException {
        User user = findByUserName(username);
        Optional<Report> optionalReport = reportRepository.findById(reportId);
        if (optionalReport.isEmpty()) {
            throw new ReportNotFoundException();
        }

        Report report = optionalReport.get();
        if (!report.getUser().equals(user)) {
            throw new ReportNotFoundException();
        }
        if (message != null && !report.getMessage().equals(message)) {
            report.setMessage(message);
        }

        return new ResponseMessage("güncellendi", true);
    }

    @Override
    public ResponseMessage changeStatus(Long reportId, ReportStatus status, String username) throws AdminNotFoundException, ReportNotFoundException {
        Report report = findById(reportId);
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null) {
            throw new AdminNotFoundException();
        }
        report.setStatus(status);
        reportRepository.save(report);
        return new ResponseMessage("durum güncellendi", true);
    }


    public Report findById(Long reportId) throws ReportNotFoundException {
        return reportRepository.findById(reportId)
                .orElseThrow(ReportNotFoundException::new);
    }


    @Override
    public ResponseMessage toggleDeleteReport(Long reportId, String username) {
        return null;
    }

    @Override
    public ResponseMessage replyToReportAsAdmin(Long reportId, String username, String message) {
        return null;
    }

    @Override
    public ResponseMessage replyToReportResponse(Long responseId, String username, String message) {
        return null;
    }

    @Override
    public ResponseMessage deleteResponse(Long responseId, String username) {
        return null;
    }

    @Override
    public ResponseMessage rateResponse(Long responseId, String username, int rating) {
        return null;
    }

    @Override
    public ResponseMessage updateRating(Long ratingId, String username, int rating) {
        return null;
    }

    @Override
    public ResponseMessage deleteRating(Long ratingId, String username) {
        return null;
    }

    @Override
    public List<?> getAllResponsesByUser(String username) {
        return List.of();
    }

    @Override
    public List<?> getReportResponses(Long reportId) {
        return List.of();
    }

    @Override
    public ResponseMessage batchToggleReports(List<Long> reportIds, boolean delete, String username) {
        return null;
    }

    @Override
    public ResponseMessage archiveReport(Long reportId, String username) {
        return null;
    }

    @Override
    public ReportStatsDTO getReportStats(String username) {
        return null;
    }

    @Override
    public Object getReportByIdAsAdmin(Long reportId) {
        return null;
    }

    @Override
    public Object getReportByIdAsUser(Long reportId, String username) {
        return null;
    }

    @Override
    public List<?> getReportsByCategoryUser(ReportCategory category, String username, Pageable pageable) {
        return List.of();
    }

    @Override
    public List<?> getReportsByCategoryAdmin(ReportCategory category, Pageable pageable) {
        return List.of();
    }

}
