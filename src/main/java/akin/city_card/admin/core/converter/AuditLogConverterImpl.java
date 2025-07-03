package akin.city_card.admin.core.converter;

import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.model.AuditLog;
import org.springframework.stereotype.Component;

@Component
public class AuditLogConverterImpl implements AuditLogConverter {
    @Override
    public AuditLogDTO mapToDto(AuditLog log) {
        AuditLogDTO dto = new AuditLogDTO();
        dto.setId(log.getId());
        dto.setAction(log.getAction());
        dto.setDescription(log.getDescription());
        dto.setTimestamp(log.getTimestamp());
        dto.setIpAddress(log.getIpAddress());
        dto.setDeviceInfo(log.getDeviceInfo());
        return dto;
    }
}
