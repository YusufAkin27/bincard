package akin.city_card.report.core.converter;

import akin.city_card.report.core.request.AddReportRequest;
import akin.city_card.report.core.response.*;
import akin.city_card.report.model.MessageAttachment;
import akin.city_card.report.model.Report;
import akin.city_card.report.model.ReportMessage;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ReportConverterImpl implements ReportConverter {


    @Override
    public Report convertToReport(AddReportRequest request, User user) {
        return null;
    }

    @Override
    public AdminReportDTO convertToAdminReportDTO(Report report) {
        return null;
    }

    @Override
    public SimpleUserDTO convertToSimpleUserDTO(User user) {
        return null;
    }

    @Override
    public SimpleAdminDTO convertToSimpleAdminDTO(SecurityUser admin) {
        return null;
    }

    @Override
    public MessageDTO convertToMessageDTO(ReportMessage reportMessage) {
        return null;
    }

    @Override
    public AttachmentDTO convertToAttachmentDTO(MessageAttachment attachment) {
        return null;
    }

    @Override
    public ReportChatDTO convertToUserChatDTO(Report report) {
        return null;
    }

    @Override
    public ReportChatDTO convertToAdminChatDTO(Report report) {
        return null;
    }
}