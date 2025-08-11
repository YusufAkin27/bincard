package akin.city_card.report.service.concretes;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Subquery;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.report.core.converter.ReportConverter;
import akin.city_card.report.core.request.CreateReportRequest;
import akin.city_card.report.core.request.SendMessageRequest;
import akin.city_card.report.core.response.*;
import akin.city_card.report.exceptions.*;
import akin.city_card.report.model.*;
import akin.city_card.report.repository.*;
import akin.city_card.report.service.abstracts.ReportService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
@Transactional
@Slf4j
public class ReportManager implements ReportService {

    private final ReportRepository reportRepository;
    private final ReportMessageRepository reportMessageRepository;
    private final MessageAttachmentRepository messageAttachmentRepository;
    private final AdminRepository adminRepository;
    private final UserRepository userRepository;
    private final SecurityUserRepository securityUserRepository;
    private final SuperAdminRepository superAdminRepository;
    private final MediaUploadService mediaUploadService;
    private final ReportConverter reportConverter;

    // ================== CORE METHODS ==================

    @Override
    @Transactional
    public ResponseMessage createReport(CreateReportRequest request, List<MultipartFile> attachments, String username)
            throws UserNotFoundException, IOException, PhotoSizeLargerException, OnlyPhotosAndVideosException,
            VideoSizeLargerException, FileFormatCouldNotException {

        User user = findUserByUsername(username);

        // Validation
        if (request.getInitialMessage() == null || request.getInitialMessage().trim().isEmpty()) {
            throw new IllegalArgumentException("Mesaj boş olamaz");
        }

        // Report oluştur
        Report report = Report.builder()
                .user(user)
                .category(request.getCategory())
                .initialMessage(request.getInitialMessage().trim())
                .status(ReportStatus.OPEN)
                .deleted(false)
                .isActive(true)
                .archived(false)
                .unreadByAdmin(1) // İlk mesaj admin için okunmamış
                .unreadByUser(0)
                .build();

        report = reportRepository.save(report);
        log.info("Report created with ID: {} by user: {}", report.getId(), username);

        // İlk mesajı oluştur
        ReportMessage firstMessage = createMessage(report, request.getInitialMessage().trim(),
                MessageSender.USER, user, null);

        // Ekleri işle
        if (attachments != null && !attachments.isEmpty()) {
            processAttachments(firstMessage, attachments);
        }

        // Report'u güncelle
        report.updateLastMessage(MessageSender.USER);
        reportRepository.save(report);

        return new ResponseMessage("Şikayet başarıyla oluşturuldu", true);
    }

    @Override
    @Transactional
    public ResponseMessage sendMessage(SendMessageRequest request, List<MultipartFile> attachments, String username)
            throws ReportNotFoundException, UserNotFoundException, IOException, UnauthorizedAreaException,
            PhotoSizeLargerException, OnlyPhotosAndVideosException, VideoSizeLargerException,
            FileFormatCouldNotException, AdminNotFoundException {

        Report report = findReportById(request.getReportId());

        // Erişim kontrolü
        if (!canAccessReport(report, username)) {
            throw new UnauthorizedAreaException();
        }

        // Validation
        if (request.getMessage() == null || request.getMessage().trim().isEmpty()) {
            throw new IllegalArgumentException("Mesaj boş olamaz");
        }

        // Gönderenin tipini belirle
        MessageSender senderType;
        User user = null;
        SecurityUser admin = null;

        if (isAdminOrSuperAdmin(username)) {
            admin = securityUserRepository.findByUserNumber(username)
                    .orElseThrow(AdminNotFoundException::new);
            senderType = MessageSender.ADMIN;
        } else {
            user = findUserByUsername(username);
            senderType = MessageSender.USER;
        }

        // Mesaj oluştur
        ReportMessage message = createMessage(report, request.getMessage().trim(), senderType, user, admin);

        // Ekleri işle
        if (attachments != null && !attachments.isEmpty()) {
            processAttachments(message, attachments);
        }

        // Report durumunu güncelle
        updateReportStatusOnMessage(report, senderType);

        log.info("Message sent to report {} by {}: {}", report.getId(), senderType, username);

        return new ResponseMessage("Mesaj başarıyla gönderildi", true);
    }

    @Override
    @Transactional
    public ResponseMessage editMessage(Long messageId, String username, String newMessage)
            throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        ReportMessage message = findMessageById(messageId);

        // Validation
        if (newMessage == null || newMessage.trim().isEmpty()) {
            throw new IllegalArgumentException("Mesaj boş olamaz");
        }

        // Yetki kontrolü - sadece kendi mesajını editleyebilir
        if (!canEditMessage(message, username)) {
            throw new UnauthorizedAreaException();
        }

        message.setMessage(newMessage.trim());
        message.setEdited(true);
        message.setEditedAt(LocalDateTime.now());

        reportMessageRepository.save(message);
        log.info("Message {} edited by {}", messageId, username);

        return new ResponseMessage("Mesaj başarıyla düzenlendi", true);
    }

    @Override
    @Transactional
    public ResponseMessage deleteMessage(Long messageId, String username)
            throws MessageNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        ReportMessage message = findMessageById(messageId);

        // Yetki kontrolü
        if (!canDeleteMessage(message, username)) {
            throw new UnauthorizedAreaException();
        }

        // Soft delete - mesaj veritabanında kalır ama silindi olarak işaretlenir
        message.setDeleted(true);
        message.setMessage("[Bu mesaj silindi]");

        reportMessageRepository.save(message);
        log.info("Message {} soft deleted by {}", messageId, username);

        return new ResponseMessage("Mesaj başarıyla silindi", true);
    }

    @Override
    public ReportChatDTO getReportChat(Long reportId, String username, Pageable pageable)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        Report report = findReportById(reportId);

        // Erişim kontrolü
        if (!canAccessReport(report, username)) {
            throw new UnauthorizedAreaException();
        }

        // Admin ve user için farklı converter kullan
        if (isAdminOrSuperAdmin(username)) {
            return reportConverter.convertToAdminChatDTO(report);
        } else {
            return reportConverter.convertToUserChatDTO(report);
        }
    }

    @Override
    public Page<MessageDTO> getReportMessages(Long reportId, String username, Pageable pageable)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        Report report = findReportById(reportId);

        // Erişim kontrolü
        if (!canAccessReport(report, username)) {
            throw new UnauthorizedAreaException();
        }

        // Admin tüm mesajları görebilir (silinenleri de), user sadece silinmemişleri
        Page<ReportMessage> messagesPage;
        if (isAdminOrSuperAdmin(username)) {
            messagesPage = reportMessageRepository.findByReportOrderBySentAtAsc(report, pageable);
        } else {
            messagesPage = reportMessageRepository.findByReportAndDeletedFalseOrderBySentAtAsc(report, pageable);
        }

        return messagesPage.map(reportConverter::convertToMessageDTO);
    }


    @Override
    @Transactional
    public ResponseMessage rateSatisfaction(Long reportId, String username, SatisfactionRatingRequest request)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException, SatisfactionAlreadyRatedException {

        Report report = findReportById(reportId);
        User user = findUserByUsername(username);

        // Sadece kendi şikayetini puanlayabilir
        if (!report.getUser().equals(user)) {
            throw new UnauthorizedAreaException();
        }

        // Zaten puanlanmış mı kontrolü
        if (report.isRated()) {
            throw new SatisfactionAlreadyRatedException();
        }

        // Puanlanabilir durumda mı kontrolü
        if (!report.canBeRated()) {
            return new ResponseMessage("Bu şikayet henüz puanlanamaz. Şikayetin çözümlenmesini bekleyiniz.", false);
        }

        // Puanı kaydet
        report.setSatisfactionRating(request.getRating(), request.getComment());
        reportRepository.save(report);

        log.info("Satisfaction rating {} given for report {} by user {}",
                request.getRating(), reportId, username);

        return new ResponseMessage("Memnuniyet puanınız kaydedildi. Teşekkür ederiz!", true);
    }

    @Override
    public Page<ReportChatDTO> getDeletedChats(String username, ReportCategory category,
                                               ReportStatus status, Pageable pageable)
            throws AdminNotFoundException {

        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        Specification<Report> spec = buildDeletedChatSpecification(category, status);
        Page<Report> reportsPage = reportRepository.findAll(spec, pageable);

        return reportsPage.map(reportConverter::convertToAdminChatDTO);
    }

    @Override
    public Page<ReportChatDTO> getAllAdminChats(String username, ReportCategory category,
                                                ReportStatus status, Boolean hasUnread,
                                                Boolean includeDeleted, Pageable pageable)
            throws AdminNotFoundException {

        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        Specification<Report> spec = buildAllAdminChatSpecification(category, status, hasUnread, includeDeleted);
        Page<Report> reportsPage = reportRepository.findAll(spec, pageable);

        return reportsPage.map(reportConverter::convertToAdminChatDTO);
    }

    @Override
    public SatisfactionStatsDTO getSatisfactionStats(String username) throws AdminNotFoundException {
        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        return buildSatisfactionStats();
    }

    @Override
    @Transactional
    public ResponseMessage restoreReport(Long reportId, String username)
            throws AdminNotFoundException, ReportNotFoundException {

        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        Report report = findReportById(reportId);

        if (!report.isDeleted()) {
            return new ResponseMessage("Bu şikayet zaten aktif durumda", false);
        }

        report.setDeleted(false);
        report.setActive(true);
        reportRepository.save(report);

        log.info("Report {} restored by admin {}", reportId, username);

        return new ResponseMessage("Şikayet başarıyla geri getirildi", true);
    }



    private Specification<Report> buildDeletedChatSpecification(ReportCategory category, ReportStatus status) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Sadece silinmiş şikayetler
            predicates.add(criteriaBuilder.equal(root.get("deleted"), true));

            if (category != null) {
                predicates.add(criteriaBuilder.equal(root.get("category"), category));
            }

            if (status != null) {
                predicates.add(criteriaBuilder.equal(root.get("status"), status));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    private Specification<Report> buildAllAdminChatSpecification(ReportCategory category, ReportStatus status,
                                                                 Boolean hasUnread, Boolean includeDeleted) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Silinmiş dahil edilsin mi?
            if (includeDeleted == null || !includeDeleted) {
                predicates.add(criteriaBuilder.equal(root.get("deleted"), false));
            }

            if (category != null) {
                predicates.add(criteriaBuilder.equal(root.get("category"), category));
            }

            if (status != null) {
                predicates.add(criteriaBuilder.equal(root.get("status"), status));
            }

            if (hasUnread != null && hasUnread) {
                predicates.add(criteriaBuilder.greaterThan(root.get("unreadByAdmin"), 0));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    private Specification<Report> buildUserChatSpecification(User user, ReportCategory category, ReportStatus status) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(criteriaBuilder.equal(root.get("user"), user));
            predicates.add(criteriaBuilder.equal(root.get("deleted"), false));
            predicates.add(criteriaBuilder.equal(root.get("isActive"), true));

            if (category != null) {
                predicates.add(criteriaBuilder.equal(root.get("category"), category));
            }

            if (status != null) {
                predicates.add(criteriaBuilder.equal(root.get("status"), status));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    private Specification<Report> buildAdminChatSpecification(ReportCategory category, ReportStatus status, Boolean hasUnread) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Admin silinmiş şikayetleri de görebilir, ama sadece aktif olanları listeler
            predicates.add(criteriaBuilder.equal(root.get("isActive"), true));

            if (category != null) {
                predicates.add(criteriaBuilder.equal(root.get("category"), category));
            }

            if (status != null) {
                predicates.add(criteriaBuilder.equal(root.get("status"), status));
            }

            if (hasUnread != null && hasUnread) {
                predicates.add(criteriaBuilder.greaterThan(root.get("unreadByAdmin"), 0));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    private Specification<Report> buildSearchSpecification(String keyword, ReportCategory category, ReportStatus status) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(criteriaBuilder.equal(root.get("isActive"), true));

            // Keyword search in initial message or messages
            if (keyword != null && !keyword.trim().isEmpty()) {
                String searchPattern = "%" + keyword.toLowerCase() + "%";

                Predicate initialMessagePredicate = criteriaBuilder.like(
                        criteriaBuilder.lower(root.get("initialMessage")), searchPattern);

                // Messages join için subquery kullan
                Subquery<Long> messageSubquery = query.subquery(Long.class);
                Root<ReportMessage> messageRoot = messageSubquery.from(ReportMessage.class);
                messageSubquery.select(messageRoot.get("report").get("id"));
                messageSubquery.where(
                        criteriaBuilder.and(
                                criteriaBuilder.equal(messageRoot.get("report"), root),
                                criteriaBuilder.like(criteriaBuilder.lower(messageRoot.get("message")), searchPattern)
                        )
                );

                Predicate messagesPredicate = criteriaBuilder.in(root.get("id")).value(messageSubquery);

                predicates.add(criteriaBuilder.or(initialMessagePredicate, messagesPredicate));
            }

            if (category != null) {
                predicates.add(criteriaBuilder.equal(root.get("category"), category));
            }

            if (status != null) {
                predicates.add(criteriaBuilder.equal(root.get("status"), status));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    private SatisfactionStatsDTO buildSatisfactionStats() {
        // Toplam puanlanan şikayet sayısı
        long totalRatedReports = reportRepository.countByIsRatedTrue();

        // Toplam puanlanabilir şikayet sayısı
        long totalRateableReports = reportRepository.countByStatusInAndIsRatedFalse(
                List.of(ReportStatus.RESOLVED, ReportStatus.REJECTED, ReportStatus.CANCELLED)
        );

        if (totalRatedReports == 0) {
            return SatisfactionStatsDTO.builder()
                    .totalRatedReports(0)
                    .totalRateableReports(totalRateableReports)
                    .averageRating(0.0)
                    .build();
        }

        // Ortalama puan
        Double averageRating = reportRepository.getAverageSatisfactionRating();

        // Puan dağılımları
        long rating1Count = reportRepository.countBySatisfactionRating(1);
        long rating2Count = reportRepository.countBySatisfactionRating(2);
        long rating3Count = reportRepository.countBySatisfactionRating(3);
        long rating4Count = reportRepository.countBySatisfactionRating(4);
        long rating5Count = reportRepository.countBySatisfactionRating(5);

        // Yüzdelik hesaplamaları
        double rating1Percentage = (rating1Count * 100.0) / totalRatedReports;
        double rating2Percentage = (rating2Count * 100.0) / totalRatedReports;
        double rating3Percentage = (rating3Count * 100.0) / totalRatedReports;
        double rating4Percentage = (rating4Count * 100.0) / totalRatedReports;
        double rating5Percentage = (rating5Count * 100.0) / totalRatedReports;

        // Memnuniyet oranı (4-5 puan alanlar)
        double satisfactionRate = ((rating4Count + rating5Count) * 100.0) / totalRatedReports;

        // Kategori bazlı ortalama puanlar
        Double lostItemAverage = reportRepository.getAverageSatisfactionRatingByCategory(ReportCategory.LOST_ITEM);
        Double driverComplaintAverage = reportRepository.getAverageSatisfactionRatingByCategory(ReportCategory.DRIVER_COMPLAINT);
        Double cardIssueAverage = reportRepository.getAverageSatisfactionRatingByCategory(ReportCategory.CARD_ISSUE);
        Double serviceDelayAverage = reportRepository.getAverageSatisfactionRatingByCategory(ReportCategory.SERVICE_DELAY);
        Double otherAverage = reportRepository.getAverageSatisfactionRatingByCategory(ReportCategory.OTHER);

        return SatisfactionStatsDTO.builder()
                .totalRatedReports(totalRatedReports)
                .totalRateableReports(totalRateableReports)
                .averageRating(averageRating != null ? averageRating : 0.0)
                .rating1Count(rating1Count)
                .rating2Count(rating2Count)
                .rating3Count(rating3Count)
                .rating4Count(rating4Count)
                .rating5Count(rating5Count)
                .rating1Percentage(rating1Percentage)
                .rating2Percentage(rating2Percentage)
                .rating3Percentage(rating3Percentage)
                .rating4Percentage(rating4Percentage)
                .rating5Percentage(rating5Percentage)
                .satisfactionRate(satisfactionRate)
                .lostItemAverage(lostItemAverage != null ? lostItemAverage : 0.0)
                .driverComplaintAverage(driverComplaintAverage != null ? driverComplaintAverage : 0.0)
                .cardIssueAverage(cardIssueAverage != null ? cardIssueAverage : 0.0)
                .serviceDelayAverage(serviceDelayAverage != null ? serviceDelayAverage : 0.0)
                .otherAverage(otherAverage != null ? otherAverage : 0.0)
                .build();
    }
    @Override
    @Transactional
    public ResponseMessage markAsRead(Long reportId, String username)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        Report report = findReportById(reportId);

        // Erişim kontrolü
        if (!canAccessReport(report, username)) {
            throw new UnauthorizedAreaException();
        }

        MessageSender readerType = isAdminOrSuperAdmin(username) ?
                MessageSender.ADMIN : MessageSender.USER;

        // Report'taki okunmamış sayacını sıfırla
        report.markAsReadBy(readerType);

        // İlgili mesajları okundu olarak işaretle
        List<ReportMessage> unreadMessages = getUnreadMessages(report, readerType);

        for (ReportMessage message : unreadMessages) {
            if (readerType == MessageSender.ADMIN) {
                message.setReadByAdmin(true);
            } else {
                message.setReadByUser(true);
            }
        }

        reportRepository.save(report);
        reportMessageRepository.saveAll(unreadMessages);

        log.info("Report {} marked as read by {} ({})", reportId, readerType, username);

        return new ResponseMessage("Mesajlar okundu olarak işaretlendi", true);
    }

    // ================== USER ENDPOINTS ==================

    @Override
    public Page<ReportChatDTO> getUserChats(String username, ReportCategory category,
                                            ReportStatus status, Pageable pageable) throws UserNotFoundException {

        User user = findUserByUsername(username);

        Specification<Report> spec = buildUserChatSpecification(user, category, status);
        Page<Report> reportsPage = reportRepository.findAll(spec, pageable);

        return reportsPage.map(reportConverter::convertToUserChatDTO);
    }

    @Override
    public int getUserUnreadCount(String username) throws UserNotFoundException {
        User user = findUserByUsername(username);
        return reportRepository.getTotalUnreadByUser(user);
    }

    @Override
    @Transactional
    public ResponseMessage deleteReportChat(Long reportId, String username)
            throws ReportNotFoundException, UserNotFoundException, UnauthorizedAreaException {

        Report report = findReportById(reportId);
        User user = findUserByUsername(username);

        // Sadece kendi şikayetini silebilir
        if (!report.getUser().equals(user)) {
            throw new UnauthorizedAreaException();
        }

        // Soft delete - admin hala görebilir
        report.setDeleted(true);
        report.setActive(false);
        report.setStatus(ReportStatus.CANCELLED);

        reportRepository.save(report);

        log.info("Report chat {} soft deleted by user {}", reportId, username);

        return new ResponseMessage("Şikayet başarıyla silindi", true);
    }

    // ================== ADMIN ENDPOINTS ==================

    @Override
    public Page<ReportChatDTO> getAdminChats(String username, ReportCategory category,
                                             ReportStatus status, Boolean hasUnread, Pageable pageable)
            throws AdminNotFoundException {

        // Admin kontrolü
        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        Specification<Report> spec = buildAdminChatSpecification(category, status, hasUnread);
        Page<Report> reportsPage = reportRepository.findAll(spec, pageable);

        return reportsPage.map(reportConverter::convertToAdminChatDTO);
    }

    @Override
    public int getAdminUnreadCount(String username) throws AdminNotFoundException {
        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        return reportRepository.getTotalUnreadByAdmin();
    }

    @Override
    @Transactional
    public ResponseMessage changeReportStatus(Long reportId, ReportStatus status, String username)
            throws AdminNotFoundException, ReportNotFoundException {

        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        Report report = findReportById(reportId);
        ReportStatus oldStatus = report.getStatus();
        report.setStatus(status);

        reportRepository.save(report);

        log.info("Report {} status changed from {} to {} by admin {}",
                reportId, oldStatus, status, username);

        return new ResponseMessage("Şikayet durumu güncellendi", true);
    }

    @Override
    @Transactional
    public ResponseMessage archiveReportChat(Long reportId, String username)
            throws AdminNotFoundException, ReportNotFoundException {

        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        Report report = findReportById(reportId);
        boolean wasArchived = report.isArchived();
        report.setArchived(!report.isArchived());

        reportRepository.save(report);

        String message = report.isArchived() ? "Şikayet arşivlendi" : "Şikayet arşivden çıkarıldı";

        log.info("Report {} archive status changed from {} to {} by admin {}",
                reportId, wasArchived, report.isArchived(), username);

        return new ResponseMessage(message, true);
    }

    @Override
    public ReportStatsDTO getReportStats(String username) throws AdminNotFoundException {
        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        return buildReportStats();
    }

    @Override
    @Transactional
    public ResponseMessage bulkArchiveReports(List<Long> reportIds, String username)
            throws AdminNotFoundException, ReportNotFoundException {

        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        List<Report> reports = reportRepository.findAllById(reportIds);

        if (reports.size() != reportIds.size()) {
            throw new ReportNotFoundException();
        }

        for (Report report : reports) {
            report.setArchived(true);
        }

        reportRepository.saveAll(reports);

        log.info("{} reports bulk archived by admin {}", reports.size(), username);

        return new ResponseMessage("Şikayetler başarıyla arşivlendi", true);
    }

    @Override
    @Transactional
    public ResponseMessage bulkChangeStatus(List<Long> reportIds, ReportStatus newStatus, String username)
            throws AdminNotFoundException, ReportNotFoundException {

        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        List<Report> reports = reportRepository.findAllById(reportIds);

        if (reports.size() != reportIds.size()) {
            throw new ReportNotFoundException();
        }

        for (Report report : reports) {
            report.setStatus(newStatus);
        }

        reportRepository.saveAll(reports);

        log.info("{} reports status changed to {} by admin {}", reports.size(), newStatus, username);

        return new ResponseMessage("Şikayet durumları başarıyla güncellendi", true);
    }

    @Override
    public Page<ReportChatDTO> searchReports(String keyword, ReportCategory category,
                                             ReportStatus status, String username, Pageable pageable)
            throws AdminNotFoundException {

        if (!isAdminOrSuperAdmin(username)) {
            throw new AdminNotFoundException();
        }

        Specification<Report> spec = buildSearchSpecification(keyword, category, status);
        Page<Report> reportsPage = reportRepository.findAll(spec, pageable);

        return reportsPage.map(reportConverter::convertToAdminChatDTO);
    }

    // ================== HELPER METHODS ==================

    private User findUserByUsername(String username) throws UserNotFoundException {
        return userRepository.findByUserNumber(username)
                .orElseThrow(() -> {
                    log.error("User not found: {}", username);
                    return new UserNotFoundException();
                });
    }

    private Report findReportById(Long reportId) throws ReportNotFoundException {
        return reportRepository.findById(reportId)
                .orElseThrow(() -> {
                    log.error("Report not found: {}", reportId);
                    return new ReportNotFoundException();
                });
    }

    private ReportMessage findMessageById(Long messageId) throws MessageNotFoundException {
        return reportMessageRepository.findById(messageId)
                .orElseThrow(() -> {
                    log.error("Message not found: {}", messageId);
                    return new MessageNotFoundException();
                });
    }

    private boolean isAdminOrSuperAdmin(String username) {
        try {
            return adminRepository.findByUserNumber(username) != null ||
                    superAdminRepository.findByUserNumber(username) != null ||
                    securityUserRepository.findByUserNumber(username).isPresent();
        } catch (Exception e) {
            log.error("Error checking admin status for user: {}", username, e);
            return false;
        }
    }

    private boolean canAccessReport(Report report, String username) throws UserNotFoundException {
        if (isAdminOrSuperAdmin(username)) {
            return true; // Admin ve SuperAdmin tüm şikayetlere erişebilir (silinenleri de)
        }

        User user = findUserByUsername(username);
        return report.getUser().equals(user) && !report.isDeleted(); // Kullanıcı sadece silinmemiş kendi şikayetine erişebilir
    }

    private boolean canEditMessage(ReportMessage message, String username) throws UserNotFoundException {
        // Admin kendi mesajını editleyebilir
        if (isAdminOrSuperAdmin(username) && message.getSender() == MessageSender.ADMIN) {
            SecurityUser admin = securityUserRepository.findByUserNumber(username)
                    .orElse(null);
            return admin != null && admin.equals(message.getAdmin());
        }

        // User kendi mesajını editleyebilir
        if (message.getSender() == MessageSender.USER) {
            User user = findUserByUsername(username);
            return user.equals(message.getUser());
        }

        return false;
    }

    private boolean canDeleteMessage(ReportMessage message, String username) throws UserNotFoundException {
        // Admin tüm mesajları silebilir
        if (isAdminOrSuperAdmin(username)) {
            return true;
        }

        // Kullanıcı sadece kendi mesajını silebilir
        if (message.getSender() == MessageSender.USER) {
            User user = findUserByUsername(username);
            return user.equals(message.getUser());
        }

        return false;
    }

    private AttachmentType determineAttachmentType(String contentType) {
        if (contentType == null) return AttachmentType.DOCUMENT;

        if (contentType.startsWith("image/")) {
            return AttachmentType.IMAGE;
        } else if (contentType.startsWith("video/")) {
            return AttachmentType.VIDEO;
        } else {
            return AttachmentType.DOCUMENT;
        }
    }

    private ReportMessage createMessage(Report report, String messageText, MessageSender senderType,
                                        User user, SecurityUser admin) {
        ReportMessage message = ReportMessage.builder()
                .report(report)
                .message(messageText)
                .sender(senderType)
                .user(user)
                .admin(admin)
                .deleted(false)
                .edited(false)
                .readByUser(senderType == MessageSender.USER)
                .readByAdmin(senderType == MessageSender.ADMIN)
                .build();

        return reportMessageRepository.save(message);
    }

    private void processAttachments(ReportMessage message, List<MultipartFile> attachments)
            throws IOException, PhotoSizeLargerException, OnlyPhotosAndVideosException,
            VideoSizeLargerException, FileFormatCouldNotException {

        List<MessageAttachment> messageAttachments = new ArrayList<>();

        for (MultipartFile file : attachments) {
            // Dosya validasyonları
            validateFile(file);

            String fileUrl = mediaUploadService.uploadAndOptimizeMedia(file);
            AttachmentType type = determineAttachmentType(file.getContentType());

            MessageAttachment attachment = MessageAttachment.builder()
                    .message(message)
                    .fileUrl(fileUrl)
                    .type(type)
                    .fileName(file.getOriginalFilename())
                    .fileSize(file.getSize())
                    .build();

            messageAttachments.add(attachment);
            messageAttachmentRepository.save(attachment);
        }

        message.setAttachments(messageAttachments);
    }

    private void validateFile(MultipartFile file) throws OnlyPhotosAndVideosException,
            PhotoSizeLargerException,
            VideoSizeLargerException,
            FileFormatCouldNotException {
        if (file == null || file.isEmpty()) {
            throw new FileFormatCouldNotException();
        }

        String contentType = file.getContentType();
        if (contentType == null) {
            throw new FileFormatCouldNotException();
        }

        // Sadece resim ve video dosyalarına izin ver
        if (!contentType.startsWith("image/") && !contentType.startsWith("video/")) {
            throw new OnlyPhotosAndVideosException();
        }

        // Dosya boyutu kontrolleri
        long fileSize = file.getSize();
        if (contentType.startsWith("image/") && fileSize > 10 * 1024 * 1024) { // 10MB
            throw new PhotoSizeLargerException();
        }
        if (contentType.startsWith("video/") && fileSize > 100 * 1024 * 1024) { // 100MB
            throw new VideoSizeLargerException();
        }
    }

    private void updateReportStatusOnMessage(Report report, MessageSender senderType) {
        if (senderType == MessageSender.ADMIN && report.getStatus() == ReportStatus.OPEN) {
            report.setStatus(ReportStatus.IN_REVIEW);
        }

        report.updateLastMessage(senderType);
        reportRepository.save(report);
    }

    private List<ReportMessage> getUnreadMessages(Report report, MessageSender readerType) {
        if (readerType == MessageSender.ADMIN) {
            return reportMessageRepository.findByReportAndReadByAdminFalse(report);
        } else {
            return reportMessageRepository.findByReportAndReadByUserFalse(report);
        }
    }





    private ReportStatsDTO buildReportStats() {
        long totalReports = reportRepository.count();
        long openReports = reportRepository.countByStatus(ReportStatus.OPEN);
        long inReviewReports = reportRepository.countByStatus(ReportStatus.IN_REVIEW);
        long resolvedReports = reportRepository.countByStatus(ReportStatus.RESOLVED);
        long rejectedReports = reportRepository.countByStatus(ReportStatus.REJECTED);
        long cancelledReports = reportRepository.countByStatus(ReportStatus.CANCELLED);
        long deletedReports = reportRepository.countByDeletedTrue();
        long archivedReports = reportRepository.countByArchivedTrue();
        long activeReports = reportRepository.countByIsActiveTrue();

        // Category stats
        long lostItemReports = reportRepository.countByCategory(ReportCategory.LOST_ITEM);
        long driverComplaintReports = reportRepository.countByCategory(ReportCategory.DRIVER_COMPLAINT);
        long cardIssueReports = reportRepository.countByCategory(ReportCategory.CARD_ISSUE);
        long serviceDelayReports = reportRepository.countByCategory(ReportCategory.SERVICE_DELAY);
        long otherReports = reportRepository.countByCategory(ReportCategory.OTHER);

        // Time-based stats
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime startOfDay = now.toLocalDate().atStartOfDay();
        LocalDateTime startOfWeek = now.minusDays(now.getDayOfWeek().getValue() - 1).toLocalDate().atStartOfDay();
        LocalDateTime startOfMonth = now.withDayOfMonth(1).toLocalDate().atStartOfDay();

        long reportsToday = reportRepository.countByCreatedAtAfter(startOfDay);
        long reportsThisWeek = reportRepository.countByCreatedAtAfter(startOfWeek);
        long reportsThisMonth = reportRepository.countByCreatedAtAfter(startOfMonth);

        // ===== YENİ EKLENEN MEMNUNIYET İSTATİSTİKLERİ =====
        SatisfactionStatsDTO satisfactionStats = buildSatisfactionStats();

        return ReportStatsDTO.builder()
                .totalReports(totalReports)
                .openReports(openReports)
                .inReviewReports(inReviewReports)
                .resolvedReports(resolvedReports)
                .rejectedReports(rejectedReports)
                .cancelledReports(cancelledReports)
                .deletedReports(deletedReports)
                .archivedReports(archivedReports)
                .activeReports(activeReports)
                .lostItemReports(lostItemReports)
                .driverComplaintReports(driverComplaintReports)
                .cardIssueReports(cardIssueReports)
                .serviceDelayReports(serviceDelayReports)
                .otherReports(otherReports)
                .reportsToday(reportsToday)
                .reportsThisWeek(reportsThisWeek)
                .reportsThisMonth(reportsThisMonth)
                .satisfactionStats(satisfactionStats)
                .build();
    }
}