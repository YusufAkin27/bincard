package akin.city_card.feedback.controller;

import akin.city_card.bus.exceptions.UnauthorizedAccessException;
import akin.city_card.feedback.service.abstracts.FeedbackStatisticsService;
import akin.city_card.response.DataResponseMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;
import java.util.Map;

@RestController
@RequestMapping("/v1/api/feedback/statistics")
@RequiredArgsConstructor
public class FeedbackStatisticsController {

    private final FeedbackStatisticsService statisticsService;

    @GetMapping("/admin/general")
    public DataResponseMessage<Map<String, Object>> getGeneralStatistics(
            @AuthenticationPrincipal UserDetails adminUser,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(adminUser);

        return statisticsService.getFeedbackStatistics(startDate, endDate);
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

    @GetMapping("/admin/anonymous-vs-user")
    public DataResponseMessage<Map<String, Long>> getAnonymousVsUserStats(
            @AuthenticationPrincipal UserDetails adminUser) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(adminUser);

        return statisticsService.getAnonymousVsUserFeedbacks();
    }
}