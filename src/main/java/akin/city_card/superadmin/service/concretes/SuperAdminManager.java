package akin.city_card.superadmin.service.concretes;

import akin.city_card.admin.model.AdminApprovalRequest;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.superadmin.service.abstracts.SuperAdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class SuperAdminManager implements SuperAdminService {
    @Override
    public DataResponseMessage<List<AdminApprovalRequest>> getPendingAdminRequest(String username) {
        return null;
    }

    @Override
    public ResponseMessage approveAdminRequest(String username, Long adminId) {
        return null;
    }

    @Override
    public ResponseMessage rejectAdminRequest(String username, Long adminId) {
        return null;
    }

    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getDailyBusIncome(String username, LocalDate date) {
        return null;
    }

    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getWeeklyBusIncome(String username, LocalDate startDate, LocalDate endDate) {
        return null;
    }

    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getMonthlyBusIncome(String username, int year, int month) {
        return null;
    }

    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getIncomeSummary(String username) {
        return null;
    }
/*
    @Override
    public DataResponseMessage<List<AuditLogDTO>> getAuditLogs(String fromDate, String toDate, String action, String username) {
        return null;
    }

 */
}
