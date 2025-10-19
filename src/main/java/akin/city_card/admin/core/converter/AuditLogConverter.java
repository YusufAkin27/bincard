package akin.city_card.admin.core.converter;

import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.model.AuditLog;

public interface AuditLogConverter {
    AuditLogDTO mapToDto(AuditLog auditLog);
}
