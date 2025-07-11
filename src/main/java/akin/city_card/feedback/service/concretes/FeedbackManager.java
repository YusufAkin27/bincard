package akin.city_card.feedback.service.concretes;

import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.feedback.core.converter.FeedbackConverter;
import akin.city_card.feedback.core.request.FeedbackRequest;
import akin.city_card.feedback.core.response.FeedbackDTO;
import akin.city_card.feedback.model.Feedback;
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
import org.springframework.data.domain.*;
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
    public ResponseMessage sendFeedback(UserDetails userDetails, FeedbackRequest request) throws OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException, VideoSizeLargerException, FileFormatCouldNotException, UserNotFoundException {
        User user = userRepository.findByUserNumber(userDetails.getUsername()).orElseThrow(UserNotFoundException::new);;

        String photoUrl = null;
        MultipartFile photo = request.getPhoto();
        if (photo != null && !photo.isEmpty()) {
            photoUrl = mediaUploadService.uploadAndOptimizeMedia(photo).join();
        }

        Feedback feedback = Feedback.builder()
                .user(user)
                .subject(request.getSubject())
                .message(request.getMessage())
                .type(request.getType())
                .source(request.getSource())
                .submittedAt(LocalDateTime.now())
                .photoUrl(photoUrl)
                .build();

        feedbackRepository.save(feedback);

        // Email gönder (eğer e-posta varsa)
        if (user.getProfileInfo().getEmail() != null && !user.getProfileInfo().getEmail().isBlank()) {
            EmailMessage email = new EmailMessage();
            email.setToEmail(user.getProfileInfo().getEmail());
            email.setSubject("Geri Bildiriminiz Alındı");
            email.setBody("Sayın kullanıcı,\n\nGeri bildiriminiz başarıyla alınmıştır. İlginiz için teşekkür ederiz.\n\nCity Card Ekibi");
            email.setHtml(false);
            mailService.queueEmail(email);
        }

        return new ResponseMessage("Geri bildiriminiz başarıyla alındı.", true);
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

        Page<Feedback> feedbackPage = feedbackRepository.findFiltered(
                type,
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
    public DataResponseMessage<FeedbackDTO> getFeedbackById(String username, Long id) {
        Optional<Feedback> feedbackOpt = feedbackRepository.findById(id);
        if (feedbackOpt.isEmpty()) {
            return new DataResponseMessage<>("Geri bildirim bulunamadı", false, null);
        }
        FeedbackDTO dto = feedbackConverter.toDTO(feedbackOpt.get());
        return new DataResponseMessage<>("Geri bildirim başarıyla getirildi", true, dto);
    }
}
