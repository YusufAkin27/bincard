package akin.city_card.superadmin.service.abstracts;

import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

public interface SuperAdminService {
    DataResponseMessage<List<AdminApprovalRequest>> getPendingAdminRequest(String username);

    ResponseMessage approveAdminRequest(String username, Long adminId);

    ResponseMessage rejectAdminRequest(String username, Long adminId);

    DataResponseMessage<Map<String, BigDecimal>> getDailyBusIncome(String username, LocalDate date);

    DataResponseMessage<Map<String, BigDecimal>> getWeeklyBusIncome(String username, LocalDate startDate, LocalDate endDate);

    DataResponseMessage<Map<String, BigDecimal>> getMonthlyBusIncome(String username, int year, int month);

    DataResponseMessage<Map<String, BigDecimal>> getIncomeSummary(String username);
}
