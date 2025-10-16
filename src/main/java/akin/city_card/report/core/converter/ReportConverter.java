package akin.city_card.report.core.converter;

import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.core.response.*;
import akin.city_card.report.model.MessageAttachment;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportMessage;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.user.model.User;

public interface ReportConverter {

    Report convertToReport(AddReportRequest request, User user);

    AdminReportDTO convertToAdminReportDTO(Report report);


    SimpleUserDTO convertToSimpleUserDTO(User user);

    SimpleAdminDTO convertToSimpleAdminDTO(SecurityUser admin);

    MessageDTO convertToMessageDTO(ReportMessage reportMessage);

    AttachmentDTO convertToAttachmentDTO(MessageAttachment attachment);

    ReportChatDTO convertToUserChatDTO(Report report);

    ReportChatDTO convertToAdminChatDTO(Report report);
}