package akin.city_card.feedback.controller;

import akin.city_card.feedback.core.request.FeedbackRequest;
import akin.city_card.feedback.core.response.FeedbackDTO;
import akin.city_card.feedback.service.abstracts.FeedbackService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.LocalDate;

@RestController
@RequestMapping("/v1/api/feedback")
@RequiredArgsConstructor
public class FeedbackController {

    private final FeedbackService feedbackService;

    // Kullanıcı geri bildirim gönderir (görsel opsiyonel)
    @PostMapping("/send")
    public ResponseMessage sendFeedback(
            @AuthenticationPrincipal UserDetails userDetails,
            @ModelAttribute @Valid FeedbackRequest request) throws UserNotFoundException, OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException, VideoSizeLargerException, FileFormatCouldNotException {
        return feedbackService.sendFeedback(userDetails, request);
    }

    @GetMapping("/admin/all")
    public DataResponseMessage<Page<FeedbackDTO>> getAllFeedbacks(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String source,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "submittedAt,desc") String sort) {

        // Sıralama parametresini parse etme
        String[] sortParams = sort.split(",");
        Sort.Direction direction = sortParams.length > 1 ?
                Sort.Direction.fromString(sortParams[1]) : Sort.Direction.DESC;

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by(direction, sortParams[0])
        );

        return feedbackService.getAllFeedbacks(
                user.getUsername(),
                type,
                source,
                start,
                end,
                pageable
        );
    }

    // Tekil geri bildirimi görüntüleme (opsiyonel)
    @GetMapping("/admin/{id}")
    public DataResponseMessage<FeedbackDTO> getFeedbackById(
            @AuthenticationPrincipal UserDetails adminUser,
            @PathVariable Long id) {
        return feedbackService.getFeedbackById(adminUser.getUsername(), id);
    }



}
