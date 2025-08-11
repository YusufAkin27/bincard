package akin.city_card.report.core.converter;

import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.core.response.*;
import akin.city_card.report.model.*;
import akin.city_card.report.repository.ReportMessageRepository;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
@RequiredArgsConstructor
public class ReportConverterImpl implements ReportConverter {

    private final ReportMessageRepository reportMessageRepository;

    @Override
    public MessageDTO convertToMessageDTO(ReportMessage message) {
        List<AttachmentDTO> attachmentDTOs = message.getAttachments() != null ?
                message.getAttachments().stream()
                        .map(this::convertToAttachmentDTO)
                        .collect(Collectors.toList()) : null;

        return MessageDTO.builder()
                .id(message.getId())
                .message(message.isDeleted() ? "[Bu mesaj silindi]" : message.getMessage())
                .sender(message.getSender())
                .user(message.getUser() != null ? convertToSimpleUserDTO(message.getUser()) : null)
                .admin(message.getAdmin() != null ? convertToSimpleAdminDTO(message.getAdmin()) : null)
                .attachments(attachmentDTOs)
                .sentAt(message.getSentAt())
                .editedAt(message.getEditedAt())
                .edited(message.isEdited())
                .deleted(message.isDeleted())
                .readByUser(message.isReadByUser())
                .readByAdmin(message.isReadByAdmin())
                .build();
    }

    @Override
    public AttachmentDTO convertToAttachmentDTO(MessageAttachment attachment) {
        return AttachmentDTO.builder()
                .id(attachment.getId())
                .fileUrl(attachment.getFileUrl())
                .type(attachment.getType())
                .fileName(attachment.getFileName())
                .fileSize(attachment.getFileSize())
                .build();
    }

    @Override
    public Report convertToReport(AddReportRequest request, User user) {
        // Report nesnesi oluştur
        Report report = Report.builder()
                .user(user)
                .category(request.getCategory())
                .initialMessage(request.getMessage())
                .status(ReportStatus.OPEN) // Yeni rapor açık başlar
                .isActive(true)
                .deleted(false)
                .archived(false)
                .unreadByAdmin(1) // İlk mesaj admin için okunmamış olarak gider
                .unreadByUser(0)
                .lastMessageSender(MessageSender.USER)
                .lastMessageAt(LocalDateTime.now())
                .build();

        // Fotoğrafları ilişkilendir
        if (request.getPhotos() != null && !request.getPhotos().isEmpty()) {
            for (ReportPhoto photo : request.getPhotos()) {
                photo.setReport(report);
                photo.setUploadedAt(LocalDateTime.now());
            }
            // Eğer Report entity'sinde photos listesi yoksa,
            // bunlar messages içine veya ayrı repo ile eklenebilir.
        }

        return report;
    }

    @Override
    public AdminReportDTO convertToAdminReportDTO(Report report) {
        // Messages null kontrolü ve güvenli stream oluşturma
        List<String> photoUrls = report.getMessages() != null ?
                report.getMessages().stream()
                        .flatMap(m -> m.getAttachments() != null ?
                                m.getAttachments().stream()
                                        .filter(att -> att.getType() == AttachmentType.IMAGE)
                                        .map(MessageAttachment::getFileUrl) :
                                Stream.empty())
                        .collect(Collectors.toList()) :
                List.of();

        List<AdminReportResponseDTO> responses = report.getMessages() != null ?
                report.getMessages().stream()
                        .filter(m -> m.getSender() == MessageSender.ADMIN)
                        .map(m -> AdminReportResponseDTO.builder()
                                .id(m.getId())
                                .responseMessage(m.getMessage())
                                .admin(m.getAdmin() != null ? convertToSimpleAdminDTO(m.getAdmin()) : null)
                                .user(m.getUser() != null ? convertToSimpleUserDTO(m.getUser()) : null)
                                .respondedAt(m.getSentAt())
                                .build())
                        .collect(Collectors.toList()) :
                List.of();

        List<UserReportResponseDTO> replies = report.getMessages() != null ?
                report.getMessages().stream()
                        .filter(m -> m.getSender() == MessageSender.USER)
                        .map(m -> UserReportResponseDTO.builder()
                                .id(m.getId())
                                .responseMessage(m.getMessage())
                                .admin(m.getAdmin() != null ? convertToSimpleAdminDTO(m.getAdmin()) : null)
                                .user(m.getUser() != null ? convertToSimpleUserDTO(m.getUser()) : null)
                                .respondedAt(m.getSentAt())
                                .build())
                        .collect(Collectors.toList()) :
                List.of();

        return AdminReportDTO.builder()
                .id(report.getId())
                .userId(report.getUser().getId())
                .userName(report.getUser().getProfileInfo() != null ?
                        report.getUser().getProfileInfo().getName() + " " + report.getUser().getProfileInfo().getSurname() :
                        "Anonim Kullanıcı")
                .category(report.getCategory())
                .message(report.getInitialMessage())
                .photoUrls(photoUrls)
                .responses(responses)
                .replies(replies)
                .status(report.getStatus())
                .createdAt(report.getCreatedAt())
                .isActive(report.isActive())
                .build();
    }

    @Override
    public SimpleUserDTO convertToSimpleUserDTO(User user) {
        return SimpleUserDTO.builder()
                .id(user.getId())
                .name(user.getProfileInfo() != null ?
                        user.getProfileInfo().getName() + " " + user.getProfileInfo().getSurname() :
                        "Anonim Kullanıcı")
                .build();
    }

    @Override
    public SimpleAdminDTO convertToSimpleAdminDTO(SecurityUser admin) {
        return SimpleAdminDTO.builder()
                .id(admin.getId())
                .name(admin.getProfileInfo() != null && admin.getProfileInfo().getName() != null ?
                        admin.getProfileInfo().getName() :
                        "Admin")
                .build();
    }

    @Override
    public ReportChatDTO convertToUserChatDTO(Report report) {
        // Son mesajı al
        Optional<ReportMessage> lastMessage = reportMessageRepository
                .findTopByReportAndDeletedFalseOrderBySentAtDesc(report);

        String lastMessageText = lastMessage.map(ReportMessage::getMessage).orElse("");

        // Son 3 mesajı al
        List<ReportMessage> recentMessages = reportMessageRepository
                .findTop3ByReportAndDeletedFalseOrderBySentAtDesc(report);

        List<MessageDTO> recentMessageDTOs = recentMessages.stream()
                .map(this::convertToMessageDTO)
                .collect(Collectors.toList());

        // Memnuniyet bilgileri
        SatisfactionRatingDTO satisfactionRating = null;
        if (report.isRated()) {
            satisfactionRating = SatisfactionRatingDTO.builder()
                    .rating(report.getSatisfactionRating())
                    .comment(report.getSatisfactionComment())
                    .ratedAt(report.getSatisfactionRatedAt())
                    .isRated(true)
                    .build();
        }

        return ReportChatDTO.builder()
                .id(report.getId())
                .user(convertToSimpleUserDTO(report.getUser()))
                .category(report.getCategory())
                .initialMessage(report.getInitialMessage())
                .status(report.getStatus())
                .createdAt(report.getCreatedAt())
                .lastMessageAt(report.getLastMessageAt())
                .lastMessageSender(report.getLastMessageSender())
                .lastMessage(lastMessageText)
                .unreadCount(report.getUnreadByUser())
                .totalMessages((int) reportMessageRepository.countByReportAndDeletedFalse(report))
                .isActive(report.isActive())
                .archived(report.isArchived())
                .deleted(report.isDeleted())
                .recentMessages(recentMessageDTOs)
                .satisfactionRating(satisfactionRating)
                .canBeRated(report.canBeRated())
                .build();
    }

    @Override
    public ReportChatDTO convertToAdminChatDTO(Report report) {
        // Son mesajı al
        Optional<ReportMessage> lastMessage = reportMessageRepository
                .findTopByReportAndDeletedFalseOrderBySentAtDesc(report);

        String lastMessageText = lastMessage.map(ReportMessage::getMessage).orElse("");

        // Son 5 mesajı al (admin için daha fazla)
        List<ReportMessage> recentMessages = reportMessageRepository
                .findTop5ByReportAndDeletedFalseOrderBySentAtDesc(report);

        List<MessageDTO> recentMessageDTOs = recentMessages.stream()
                .map(this::convertToMessageDTO)
                .collect(Collectors.toList());

        // Memnuniyet bilgileri
        SatisfactionRatingDTO satisfactionRating = null;
        if (report.isRated()) {
            satisfactionRating = SatisfactionRatingDTO.builder()
                    .rating(report.getSatisfactionRating())
                    .comment(report.getSatisfactionComment())
                    .ratedAt(report.getSatisfactionRatedAt())
                    .isRated(true)
                    .build();
        }

        return ReportChatDTO.builder()
                .id(report.getId())
                .user(convertToSimpleUserDTO(report.getUser()))
                .category(report.getCategory())
                .initialMessage(report.getInitialMessage())
                .status(report.getStatus())
                .createdAt(report.getCreatedAt())
                .lastMessageAt(report.getLastMessageAt())
                .lastMessageSender(report.getLastMessageSender())
                .lastMessage(lastMessageText)
                .unreadCount(report.getUnreadByAdmin())
                .totalMessages((int) reportMessageRepository.countByReportAndDeletedFalse(report))
                .isActive(report.isActive())
                .archived(report.isArchived())
                .deleted(report.isDeleted())
                .recentMessages(recentMessageDTOs)
                .satisfactionRating(satisfactionRating)
                .canBeRated(report.canBeRated())
                .build();
    }
}