package akin.city_card.feedback.service.abstracts;

import akin.city_card.feedback.core.request.AnonymousFeedbackRequest;
import akin.city_card.feedback.core.request.FeedbackRequest;
import akin.city_card.feedback.core.response.FeedbackDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.IOException;
import java.time.LocalDate;

public interface FeedbackService {
    // Giriş yapmış kullanıcı için feedback
    ResponseMessage sendFeedback(UserDetails userDetails, FeedbackRequest request)
            throws OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException,
            VideoSizeLargerException, FileFormatCouldNotException, UserNotFoundException;

    // Anonim kullanıcı için feedback
    ResponseMessage sendAnonymousFeedback(AnonymousFeedbackRequest request)
            throws OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException,
            VideoSizeLargerException, FileFormatCouldNotException;

    DataResponseMessage<FeedbackDTO> getFeedbackById(String username, Long id);

    DataResponseMessage<Page<FeedbackDTO>> getAllFeedbacks(String username, String type, String source, LocalDate start, LocalDate end, Pageable pageable);

    // Anonim durumu filtresi ile birlikte feedback'leri getirme
    DataResponseMessage<Page<FeedbackDTO>> getAllFeedbacksWithAnonymousFilter(
            String username, String type, String source, Boolean isAnonymous,
            LocalDate start, LocalDate end, Pageable pageable);
}