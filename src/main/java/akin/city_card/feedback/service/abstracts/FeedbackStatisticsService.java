package akin.city_card.feedback.service.abstracts;

import akin.city_card.feedback.repository.FeedbackRepository;
import akin.city_card.response.DataResponseMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class FeedbackStatisticsService {

    private final FeedbackRepository feedbackRepository;

    public DataResponseMessage<Map<String, Object>> getFeedbackStatistics(
            LocalDate startDate,
            LocalDate endDate) {

        LocalDateTime startDateTime = startDate != null ?
                startDate.atStartOfDay() : LocalDateTime.of(2000, 1, 1, 0, 0);
        LocalDateTime endDateTime = endDate != null ?
                endDate.atTime(23, 59, 59) : LocalDateTime.now();

        Map<String, Object> statistics = new HashMap<>();

        // Toplam feedback sayısı
        long totalFeedbacks = feedbackRepository.count();
        statistics.put("totalFeedbacks", totalFeedbacks);

        // Türe göre istatistikler
        List<Object[]> typeStats = feedbackRepository.getFeedbackStatsByType(startDateTime, endDateTime);
        statistics.put("feedbacksByType", typeStats);

        // Kaynağa göre istatistikler
        List<Object[]> sourceStats = feedbackRepository.getFeedbackStatsBySource(startDateTime, endDateTime);
        statistics.put("feedbacksBySource", sourceStats);

        // Aylık istatistikler
        List<Object[]> monthlyStats = feedbackRepository.getMonthlyFeedbackStats(startDateTime, endDateTime);
        statistics.put("monthlyFeedbacks", monthlyStats);

        // Günlük istatistikler (son 30 gün)
        LocalDateTime last30Days = LocalDateTime.now().minusDays(30);
        List<Object[]> dailyStats = feedbackRepository.getDailyFeedbackStats(last30Days, LocalDateTime.now());
        statistics.put("dailyFeedbacks", dailyStats);

        // Anonim vs Kullanıcı istatistikleri
        Object[] anonymousVsUserStats = feedbackRepository.getAnonymousVsUserStats(startDateTime, endDateTime);
        statistics.put("anonymousVsUser", anonymousVsUserStats);

        return new DataResponseMessage<>(
                "Feedback istatistikleri başarıyla getirildi.",
                true,
                statistics
        );
    }

    public DataResponseMessage<Map<String, Long>> getAnonymousVsUserFeedbacks() {
        Map<String, Long> stats = new HashMap<>();

        long anonymousFeedbacks = feedbackRepository.findAnonymousFeedbacks(
                org.springframework.data.domain.PageRequest.of(0, Integer.MAX_VALUE)
        ).getTotalElements();

        long userFeedbacks = feedbackRepository.findUserFeedbacks(
                org.springframework.data.domain.PageRequest.of(0, Integer.MAX_VALUE)
        ).getTotalElements();

        stats.put("anonymousFeedbacks", anonymousFeedbacks);
        stats.put("userFeedbacks", userFeedbacks);
        stats.put("totalFeedbacks", anonymousFeedbacks + userFeedbacks);

        return new DataResponseMessage<>(
                "Anonim vs Kullanıcı feedback istatistikleri başarıyla getirildi.",
                true,
                stats
        );
    }
}