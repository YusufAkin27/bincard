package akin.city_card.feedback.service.abstracts;

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
    ResponseMessage sendFeedback(UserDetails userDetails, FeedbackRequest request) throws OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException, VideoSizeLargerException, FileFormatCouldNotException, UserNotFoundException;


    DataResponseMessage<FeedbackDTO> getFeedbackById(String username, Long id);

    DataResponseMessage<Page<FeedbackDTO>> getAllFeedbacks(String username, String type, String source, LocalDate start, LocalDate end, Pageable pageable);
}
