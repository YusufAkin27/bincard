package akin.city_card.feedback.service.concretes;

import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.feedback.core.converter.FeedbackConverter;
import akin.city_card.feedback.core.request.AnonymousFeedbackRequest;
import akin.city_card.feedback.core.request.FeedbackRequest;
import akin.city_card.feedback.core.response.FeedbackDTO;
import akin.city_card.feedback.model.Feedback;
import akin.city_card.feedback.model.FeedbackType;
import akin.city_card.feedback.repository.FeedbackRepository;
import akin.city_card.feedback.service.abstracts.FeedbackService;
import akin.city_card.mail.EmailMessage;
import akin.city_card.mail.MailService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class FeedbackManager implements FeedbackService {

    private final FeedbackRepository feedbackRepository;
    private final UserRepository userRepository;
    private final MediaUploadService mediaUploadService;
    private final MailService mailService;
    private final FeedbackConverter feedbackConverter;

    @Override
    public ResponseMessage sendFeedback(UserDetails userDetails, FeedbackRequest request)
            throws OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException,
            VideoSizeLargerException, FileFormatCouldNotException, UserNotFoundException {

        User user = userRepository.findByUserNumber(userDetails.getUsername())
                .orElseThrow(UserNotFoundException::new);

        String photoUrl = uploadPhotoIfExists(request.getPhoto());

        Feedback feedback = Feedback.builder()
                .user(user)
                .subject(request.getSubject())
                .message(request.getMessage())
                .type(request.getType())
                .source(request.getSource())
                .submittedAt(LocalDateTime.now())
                .photoUrl(photoUrl)
                .isAnonymous(false) // Kayıtlı kullanıcı
                .build();

        feedbackRepository.save(feedback);

        // Email gönder (eğer e-posta varsa)
        sendConfirmationEmail(feedback);

        return new ResponseMessage("Geri bildiriminiz başarıyla alındı.", true);
    }

    @Override
    public ResponseMessage sendAnonymousFeedback(AnonymousFeedbackRequest request)
            throws OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException,
            VideoSizeLargerException, FileFormatCouldNotException {

        String photoUrl = uploadPhotoIfExists(request.getPhoto());

        Feedback feedback = Feedback.builder()
                .user(null) // Anonim kullanıcı
                .subject(request.getSubject())
                .message(request.getMessage())
                .type(request.getType())
                .source(request.getSource())
                .submittedAt(LocalDateTime.now())
                .photoUrl(photoUrl)
                .contactEmail(request.getContactEmail())
                .contactName(request.getContactName())
                .contactPhone(request.getContactPhone())
                .isAnonymous(true)
                .build();

        feedbackRepository.save(feedback);

        // Email gönder (eğer contact email varsa)
        sendConfirmationEmail(feedback);

        return new ResponseMessage("Geri bildiriminiz başarıyla alındı.", true);
    }

    private String uploadPhotoIfExists(MultipartFile photo)
            throws OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException,
            VideoSizeLargerException, FileFormatCouldNotException {

        if (photo != null && !photo.isEmpty()) {
            return mediaUploadService.uploadAndOptimizeMedia(photo);
        }
        return null;
    }

    private void sendConfirmationEmail(Feedback feedback) {
        String effectiveEmail = feedback.getEffectiveContactEmail();
        String effectiveName = feedback.getEffectiveContactName();

        if (effectiveEmail != null && !effectiveEmail.isBlank()) {
            EmailMessage email = new EmailMessage();
            email.setToEmail(effectiveEmail);
            email.setSubject("Geri Bildiriminiz Alındı");

            String greeting = effectiveName != null && !effectiveName.isBlank()
                    ? "Sayın " + effectiveName + ","
                    : "Sayın kullanıcı,";

            String body = greeting + "\n\n" +
                    "Geri bildiriminiz başarıyla alınmıştır. " +
                    "İlginiz için teşekkür ederiz.\n\n" +
                    "Konu: " + feedback.getSubject() + "\n" +
                    "Tarih: " + feedback.getSubmittedAt().toLocalDate() + "\n\n" +
                    "City Card Ekibi";

            email.setBody(body);
            email.setHtml(false);
            mailService.queueEmail(email);
        }
    }

    @Override
    public DataResponseMessage<Page<FeedbackDTO>> getAllFeedbacks(
            String username,
            String type,
            String source,
            LocalDate start,
            LocalDate end,
            Pageable pageable) {

        // Tarih aralığı ayarlamaları
        LocalDateTime startDateTime = (start != null) ? start.atStartOfDay() : LocalDateTime.of(2000, 1, 1, 0, 0);
        LocalDateTime endDateTime = (end != null) ? end.atTime(23, 59, 59) : LocalDateTime.now();

        // String type'ı FeedbackType enum'ına dönüştür
        FeedbackType feedbackType = null;
        if (type != null && !type.trim().isEmpty()) {
            try {
                feedbackType = FeedbackType.valueOf(type.toUpperCase());
            } catch (IllegalArgumentException e) {
                return new DataResponseMessage<>(
                        "Geçersiz feedback türü: " + type,
                        false,
                        Page.empty()
                );
            }
        }

        Page<Feedback> feedbackPage = feedbackRepository.findFiltered(
                feedbackType,
                source,
                startDateTime,
                endDateTime,
                pageable
        );

        return new DataResponseMessage<>(
                "Geri bildirimler başarıyla getirildi.",
                true,
                feedbackPage.map(feedbackConverter::toDTO)
        );
    }

    @Override
    public DataResponseMessage<Page<FeedbackDTO>> getAllFeedbacksWithAnonymousFilter(
            String username,
            String type,
            String source,
            Boolean isAnonymous,
            LocalDate start,
            LocalDate end,
            Pageable pageable) {

        // Tarih aralığı ayarlamaları
        LocalDateTime startDateTime = (start != null) ? start.atStartOfDay() : LocalDateTime.of(2000, 1, 1, 0, 0);
        LocalDateTime endDateTime = (end != null) ? end.atTime(23, 59, 59) : LocalDateTime.now();

        // String type'ı FeedbackType enum'ına dönüştür
        FeedbackType feedbackType = null;
        if (type != null && !type.trim().isEmpty()) {
            try {
                feedbackType = FeedbackType.valueOf(type.toUpperCase());
            } catch (IllegalArgumentException e) {
                return new DataResponseMessage<>(
                        "Geçersiz feedback türü: " + type,
                        false,
                        Page.empty()
                );
            }
        }

        Page<Feedback> feedbackPage = feedbackRepository.findFilteredWithAnonymous(
                feedbackType,
                source,
                isAnonymous,
                startDateTime,
                endDateTime,
                pageable
        );

        return new DataResponseMessage<>(
                "Geri bildirimler başarıyla getirildi.",
                true,
                feedbackPage.map(feedbackConverter::toDTO)
        );
    }

    @Override
    public DataResponseMessage<FeedbackDTO> getFeedbackById(String username, Long id) {
        Optional<Feedback> feedbackOpt = feedbackRepository.findById(id);
        if (feedbackOpt.isEmpty()) {
            return new DataResponseMessage<>("Geri bildirim bulunamadı", false, null);
        }
        FeedbackDTO dto = feedbackConverter.toDTO(feedbackOpt.get());
        return new DataResponseMessage<>("Geri bildirim başarıyla getirildi", true, dto);
    }
}