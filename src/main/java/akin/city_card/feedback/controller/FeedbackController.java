package akin.city_card.feedback.controller;

import akin.city_card.bus.exceptions.UnauthorizedAccessException;
import akin.city_card.feedback.core.request.AnonymousFeedbackRequest;
import akin.city_card.feedback.core.request.FeedbackRequest;
import akin.city_card.feedback.core.response.FeedbackDTO;
import akin.city_card.feedback.model.FeedbackType;
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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/v1/api/feedback")
@RequiredArgsConstructor
public class FeedbackController {

    private final FeedbackService feedbackService;

    // Giriş yapmış kullanıcı geri bildirim gönderir
    @PostMapping("/send")
    public ResponseMessage sendFeedback(
            @AuthenticationPrincipal UserDetails userDetails,
            @ModelAttribute @Valid FeedbackRequest request)
            throws UserNotFoundException, OnlyPhotosAndVideosException, PhotoSizeLargerException,
            IOException, VideoSizeLargerException, FileFormatCouldNotException {
        return feedbackService.sendFeedback(userDetails, request);
    }

    // Anonim kullanıcı geri bildirim gönderir (giriş gerektirmez)
    @PostMapping("/send-anonymous")
    public ResponseMessage sendAnonymousFeedback(
            @ModelAttribute @Valid AnonymousFeedbackRequest request)
            throws OnlyPhotosAndVideosException, PhotoSizeLargerException,
            IOException, VideoSizeLargerException, FileFormatCouldNotException {
        return feedbackService.sendAnonymousFeedback(request);
    }

    // Genel feedback gönderme endpoint'i (hem giriş yapmış hem anonim kullanıcılar için)
    @PostMapping("/send-general")
    public ResponseMessage sendGeneralFeedback(
            @AuthenticationPrincipal UserDetails userDetails, // Opsiyonel - null olabilir
            @ModelAttribute @Valid AnonymousFeedbackRequest request)
            throws OnlyPhotosAndVideosException, PhotoSizeLargerException,
            IOException, VideoSizeLargerException, FileFormatCouldNotException, UserNotFoundException {

        // Eğer kullanıcı giriş yapmışsa, mevcut request'i FeedbackRequest'e dönüştür
        if (userDetails != null) {
            FeedbackRequest userRequest = new FeedbackRequest();
            userRequest.setSubject(request.getSubject());
            userRequest.setMessage(request.getMessage());
            userRequest.setType(request.getType());
            userRequest.setSource(request.getSource());
            userRequest.setPhoto(request.getPhoto());

            return feedbackService.sendFeedback(userDetails, userRequest);
        } else {
            // Anonim kullanıcı olarak işle
            return feedbackService.sendAnonymousFeedback(request);
        }
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
            @RequestParam(defaultValue = "submittedAt,desc") String sort,
            @RequestParam(required = false) Boolean isAnonymous) throws UnauthorizedAccessException {

        isAdminOrSuperAdmin(user);

        // Sıralama parametresini parse etme
        String[] sortParams = sort.split(",");
        Sort.Direction direction = sortParams.length > 1 ?
                Sort.Direction.fromString(sortParams[1]) : Sort.Direction.DESC;

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by(direction, sortParams[0])
        );

        // Eğer isAnonymous filtresi varsa, genişletilmiş metodu kullan
        if (isAnonymous != null) {
            return feedbackService.getAllFeedbacksWithAnonymousFilter(
                    user.getUsername(),
                    type,
                    source,
                    isAnonymous,
                    start,
                    end,
                    pageable
            );
        } else {
            return feedbackService.getAllFeedbacks(
                    user.getUsername(),
                    type,
                    source,
                    start,
                    end,
                    pageable
            );
        }
    }

    private void isAdminOrSuperAdmin(UserDetails userDetails) throws UnauthorizedAccessException {
        if (userDetails == null || userDetails.getAuthorities() == null) {
            throw new UnauthorizedAccessException();
        }

        boolean authorized = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ADMIN") || role.equals("SUPERADMIN"));

        if (!authorized) {
            throw new UnauthorizedAccessException();
        }
    }

    // Tekil geri bildirimi görüntüleme
    @GetMapping("/admin/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public DataResponseMessage<FeedbackDTO> getFeedbackById(
            @AuthenticationPrincipal UserDetails adminUser,
            @PathVariable Long id) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(adminUser);
        return feedbackService.getFeedbackById(adminUser.getUsername(), id);
    }

    // Public endpoint - feedback türlerini getir (giriş gerektirmez)
    @GetMapping("/types")
    public DataResponseMessage<Map<String, String>> getFeedbackTypes() {
        Map<String, String> types = new HashMap<>();
        for (FeedbackType type : FeedbackType.values()) {
            String description = switch (type) {
                case SUGGESTION -> "Öneri";
                case COMPLAINT -> "Şikayet";
                case TECHNICAL_ISSUE -> "Teknik Hata";
                case OTHER -> "Diğer";
            };
            types.put(type.name(), description);
        }

        return new DataResponseMessage<>(
                "Feedback türleri başarıyla getirildi.",
                true,
                types
        );
    }
}