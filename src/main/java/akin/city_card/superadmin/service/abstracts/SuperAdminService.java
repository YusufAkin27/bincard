package akin.city_card.superadmin.service.abstracts;

import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.admin.model.ApprovalStatus;
import akin.city_card.admin.model.AuditLog;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.SuperAdminNotFoundException;
import akin.city_card.superadmin.core.response.AdminApprovalRequestDTO;
import akin.city_card.superadmin.exceptions.AdminApprovalRequestNotFoundException;
import akin.city_card.superadmin.exceptions.RequestAlreadyProcessedException;
import org.hibernate.query.Page;
import org.springframework.data.domain.Pageable;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

public interface SuperAdminService {

    ResponseMessage approveAdminRequest(String username, Long requestId) throws AdminNotFoundException, AdminApprovalRequestNotFoundException, RequestAlreadyProcessedException;

    ResponseMessage rejectAdminRequest(String username, Long adminId) throws AdminNotFoundException, RequestAlreadyProcessedException, AdminApprovalRequestNotFoundException;

    DataResponseMessage<Map<String, BigDecimal>> getDailyBusIncome(String username, LocalDate date);

    DataResponseMessage<Map<String, BigDecimal>> getWeeklyBusIncome(String username, LocalDate startDate, LocalDate endDate);

    DataResponseMessage<Map<String, BigDecimal>> getMonthlyBusIncome(String username, int year, int month);

    DataResponseMessage<Map<String, BigDecimal>> getIncomeSummary(String username);

    DataResponseMessage<List<AdminApprovalRequest>> getPendingAdminRequest(String username, Pageable pageable) throws SuperAdminNotFoundException;

    DataResponseMessage<List<AuditLogDTO>> getAuditLogs(String fromDate, String toDate, String action, String username);

}
