package akin.city_card.report.core.converter;

import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.core.response.*;
import akin.city_card.user.model.User;
import org.springframework.stereotype.Component;
import akin.city_card.report.model.*;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class ReportConverterImpl implements ReportConverter {

    @Override
    public Report convertToReport(AddReportRequest request, User user) {
        return Report.builder()
                .user(user)
                .category(request.getCategory())
                .message(request.getMessage())
                .photos(request.getPhotos() != null ? request.getPhotos().stream()
                        .peek(photo -> photo.setReport(null)) // ilişkiler sonra kurulabilir
                        .collect(Collectors.toList()) : null)
                .status(ReportStatus.OPEN)
                .isActive(true)
                .deleted(false)
                .build();
    }

    @Override
    public AdminReportDTO convertToAdminReportDTO(Report report) {
        return AdminReportDTO.builder()
                .id(report.getId())
                .userId(report.getUser().getId())
                .userName(report.getUser().getName())
                .category(report.getCategory())
                .message(report.getMessage())
                .photoUrls(report.getPhotos().stream().map(ReportPhoto::getImageUrl).toList())
                .responses(report.getResponses().stream().map(this::convertToAdminResponseDTO).toList())
                .status(report.getStatus())
                .createdAt(report.getCreatedAt())
                .isActive(report.isActive())
                .build();
    }

    @Override
    public UserReportDTO convertToUserReportDTO(Report report) {
        return UserReportDTO.builder()
                .id(report.getId())
                .category(report.getCategory())
                .message(report.getMessage())
                .photoUrls(report.getPhotos().stream().map(ReportPhoto::getImageUrl).toList())
                .responses(report.getResponses().stream().map(this::convertToUserResponseDTO).toList())
                .status(report.getStatus())
                .createdAt(report.getCreatedAt())
                .build();
    }

    @Override
    public AdminReportResponseDTO convertToAdminResponseDTO(ReportResponse response) {
        return AdminReportResponseDTO.builder()
                .id(response.getId())
                .responseMessage(response.getResponseMessage())
                .admin(response.getAdmin() != null ?
                        new SimpleAdminDTO(response.getAdmin().getId(), response.getAdmin().getName()) : null)
                .user(response.getUser() != null ?
                        new SimpleUserDTO(response.getUser().getId(), response.getUser().getName()) : null)
                .replies(response.getReplies().stream()
                        .map(this::convertToAdminResponseDTO)
                        .toList())
                .respondedAt(response.getRespondedAt())
                .ratings(response.getRatings() != null ? response.getRatings().stream()
                        .map(this::convertToRatingDTO)
                        .toList() : List.of())
                .build();
    }

    @Override
    public UserReportResponseDTO convertToUserResponseDTO(ReportResponse response) {
        return UserReportResponseDTO.builder()
                .id(response.getId())
                .responseMessage(response.getResponseMessage())
                .admin(response.getAdmin() != null ? new SimpleAdminDTO(response.getAdmin().getId(), response.getAdmin().getName()) : null)
                .user(response.getUser() != null ? new SimpleUserDTO(response.getUser().getId(), response.getUser().getName()) : null)
                .replies(response.getReplies().stream().map(this::convertToUserResponseDTO).toList())
                .respondedAt(response.getRespondedAt())
                .build();
    }

    @Override
    public ReportResponseRatingDTO convertToRatingDTO(ReportResponseRating rating) {
        return ReportResponseRatingDTO.builder()
                .userId(rating.getUser().getId())
                .rating(rating.getRating())
                .build();
    }
}
