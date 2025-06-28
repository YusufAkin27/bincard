package akin.city_card.report.core.converter;

import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.core.response.*;
import akin.city_card.report.model.*;
import akin.city_card.user.model.User;

public interface ReportConverter {

    Report convertToReport(AddReportRequest request, User user);

    AdminReportDTO convertToAdminReportDTO(Report report);

    UserReportDTO convertToUserReportDTO(Report report);

    AdminReportResponseDTO convertToAdminResponseDTO(ReportResponse response);

    UserReportResponseDTO convertToUserResponseDTO(ReportResponse response);

    ReportResponseRatingDTO convertToRatingDTO(ReportResponseRating rating);
}
